# Durable crawl queue (Postgres lease queue)

Status: proposed / in progress
Inspired by the push + durability model in joinmastodon-api (Sidekiq), re-expressed
in vmcrawl's stack (Python + Postgres, no broker).

## Why

Today a crawl run is a one-shot batch:

1. `load_from_database()` runs a category SELECT and materializes the whole result
   into a Python list (`crawler.py`).
2. `check_and_record_domains()` loads that list into an in-memory `asyncio.Queue`,
   drains it with N workers, and exits.
3. In headless mode the outer loop just re-SELECTs the *entire* eligible set every
   cycle (random-shuffled) and re-crawls everything as fast as it can.

Consequences:

- **No durability of in-flight work.** A crash mid-cycle loses the queue. Nothing
  records that a domain was being worked on, so there is no clean resume.
- **No notion of "due."** Every cycle re-crawls everything; there is no per-domain
  recrawl cadence and no way to prioritize what actually needs attention.
- **Retries are manual.** Transient failures sit until an operator runs a retry
  menu choice (options 4/5/20–32). There is no automatic backoff.

joinmastodon-api gets all three for free because each domain is an independent,
durable Sidekiq message with an `ignore_until` schedule and an error-count backoff.
We get the same properties **without adding Redis or a broker** by treating
`raw_domains` — which is already our durable ledger — as the work queue, and adding
queue-discipline columns + a `SELECT … FOR UPDATE SKIP LOCKED` claim loop.

## Design goals

- **Additive and opt-in.** Existing menu / `--file` / `--target` / `fetch` / `manage`
  modes are unchanged. The queue daemon is a new path behind a flag, so production
  behavior does not change until it is deliberately turned on.
- **No new infrastructure.** Everything lives in the Postgres we already run.
- **Crash-safe.** A worker that dies leaves a lease that expires and is re-claimed.
- **Self-scheduling.** A domain becomes due on its own cadence; the daemon sleeps
  when nothing is due instead of hammering the table.
- **Auto-revival preserved.** Dead/terminal domains are not abandoned forever; they
  are rescheduled far out (default 30d) so revived servers get re-counted — the
  joinmastodon-api property we liked.

## Schema changes (`database.sql`)

Added to `raw_domains` (all idempotent `ADD COLUMN IF NOT EXISTS`):

| Column          | Type          | Meaning                                                        |
| --------------- | ------------- | -------------------------------------------------------------- |
| `next_crawl_at` | `TIMESTAMPTZ` | When this domain is next due. `NULL` = never crawled = due now |
| `claimed_at`    | `TIMESTAMPTZ` | Lease start. `NULL` = unclaimed                                |
| `claimed_by`    | `TEXT`        | Worker identity holding the lease (host/pid) — observability   |
| `attempts`      | `INTEGER`     | Consecutive transient failures; drives backoff. Reset on success |

`attempts` is intentionally separate from the existing `errors` column: `errors` is
a diagnostic counter (and is nulled for Mastodon-compatible domains), whereas
`attempts` is purely the scheduling concern. Keeping them separate avoids coupling
backoff to display semantics.

Index supporting the claim query:

```sql
CREATE INDEX IF NOT EXISTS idx_raw_domains_due
    ON raw_domains (next_crawl_at NULLS FIRST)
    WHERE (alias IS NULL OR alias = FALSE);
```

Backfill jitters existing rows across their interval so the first daemon start does
not stampede every row at once (never-failed → due now / within ~1h; rows with a
recorded `reason` → spread over the cap interval ~30d). The queue then reschedules
each row precisely on its next claim.

## Claim semantics

One atomic statement claims a batch and returns it, skipping rows another worker
already holds:

```sql
WITH due AS (
    SELECT domain
    FROM raw_domains
    WHERE (next_crawl_at IS NULL OR next_crawl_at <= now())
      AND (claimed_at IS NULL OR claimed_at <= now() - make_interval(secs => %(lease)s))
      AND (alias IS NULL OR alias = FALSE)
      AND NOT EXISTS (                       -- hard-DNI domains are never claimed
          SELECT 1 FROM dni d
          WHERE d.force = 'hard'
            AND (raw_domains.domain = d.domain
                 OR right(raw_domains.domain, char_length(d.domain) + 1)
                    = '.' || d.domain)
      )
    ORDER BY next_crawl_at ASC NULLS FIRST
    LIMIT %(batch)s
    FOR UPDATE SKIP LOCKED
)
UPDATE raw_domains r
SET claimed_at = now(), claimed_by = %(worker)s
FROM due
WHERE r.domain = due.domain
RETURNING r.domain;
```

- `FOR UPDATE SKIP LOCKED` is the same safe concurrent-dequeue primitive Sidekiq gets
  from Redis, but transactional in the DB we already have.
- **Known non-Mastodon domains are still claimed and rechecked** on the long
  `nonmasto` cadence (default 7d) rather than being excluded, so a domain that
  *migrates* to Mastodon from other software is eventually re-detected. The cost
  is cheap: a non-Mastodon recrawl is a single nodeinfo fetch.
- **Known failure domains are still claimed and recrawled.** There are no
  terminal `bad_*` flags — scheduling is derived entirely from `reason` (see
  *Reschedule policy*). Every failed domain is claimed once due and actually
  re-attempted, on a per-type cadence (a 5xx returns in hours, a DNS failure
  backs off toward 30d, a `HARD`/`ROBOT` domain on a long flat interval), so
  revived servers are eventually re-counted rather than abandoned.
- **The worker skips no domain on its recorded state in queue mode**
  (`bypass_skip_filters=True`), because the claim query above is the
  authoritative filter — every domain it hands back is meant to be (re)crawled.
  Without this, a re-claimed not-Mastodon domain would be claimed only to be
  skipped by the in-process state filter and rescheduled untouched, silently
  defeating migration re-detection. The only permanent exclusions are aliases and
  hard-DNI.
- **Hard-DNI domains are never claimed.** The `NOT EXISTS` clause mirrors the
  worker-side label-boundary match in `_is_dni_domain`, so a `dni` entry with
  `force = 'hard'` keeps out the domain itself and any subdomain of it
  (`example.com` excludes `example.com` and `a.b.example.com`) but not an
  unrelated domain that merely contains the string (`notexample.com`,
  `example.community`). (Soft-DNI is recorded but not enforced, matching
  existing behavior.) Note: this means hard-DNI rows already in `raw_domains` are no
  longer crawled, but the daemon also won't *purge* them the way an in-worker
  encounter does — they simply sit unclaimed. Purge still happens via the manage/fetch
  paths.
- The lease-expiry clause (`claimed_at <= now() - lease`) means the claim query
  **self-heals**: a crashed worker's domains become re-claimable once the lease ages
  out. No separate janitor is strictly required; `reclaim_stale_leases()` exists only
  to tidy/observe leases left by a previous crashed process at startup.

## Reschedule policy

After a domain is processed, one UPDATE clears the lease and sets the next due time,
deriving the interval entirely from `reason` (the latest failure classification) and
`attempts` (consecutive failures) — so it is correct regardless of which Python code
path recorded the result. There are no terminal `bad_*` columns:

```text
next_crawl_at = now() + CASE
    WHEN reason IS NOT NULL              THEN least(base(reason) * 2^attempts,
                                                    greatest(base(reason), cap))
    WHEN nodeinfo IS NOT NULL
         AND nodeinfo NOT IN (masto set) THEN nonmasto_interval  -- known non-Mastodon
    ELSE                                      recrawl_interval   -- healthy
END
attempts = CASE WHEN reason IS NOT NULL THEN attempts + 1 ELSE 0 END
claimed_at = NULL, claimed_by = NULL
```

`base(reason)` is a per-type cadence selected from the leading token of `reason`
(`_REASON_BASE_HOURS_CASE`). Transient types use short bases and back off
exponentially with `attempts` up to `cap` (default 30d); `ROBOT` and `HARD` use
long flat bases that already exceed the cap, so `greatest(base, cap)` pins them flat
(backoff is a no-op). This generalizes joinmastodon-api's split — 5xx/timeouts
recover fast, 4xx and gone/disallowed states settle far out — into a per-type table:

| reason type                         | base    | behavior                          |
| ----------------------------------- | ------- | --------------------------------- |
| `HTTP5XX`                           | 6h      | up but erroring — recovers fast   |
| `TCP`                               | 12h     | unreachable, maybe transient      |
| `DNS` / `SSL` / content (`TYPE`/`FILE`/`JSON`/`API`) | 24h | daily, backs off    |
| `HTTP2XX` / `HTTP3XX` / `HTTP4XX`   | 48h     | semi-permanent client/redirect    |
| `ROBOT`                             | 720h    | disallowed — extended, flat       |
| `HARD` (410/451/418/999 gone)       | 2160h   | gone — very long, flat            |

`HARD` and `ROBOT` are the only classifications that also purge the domain from the
published `mastodon_domains` list, at detection. Every other failure leaves the
published row untouched (last-known-good).

## Daemon loop

The opt-in queue daemon replaces the headless whole-batch re-select with:

```text
reclaim_stale_leases()              # clear leases from a prior crashed process
loop:
    domains = claim_due_domains(batch, lease, worker_id)
    if not domains:
        sleep(poll_interval)        # nothing due; back off instead of hammering
        continue
    process each domain via existing process_domain() pipeline (N workers)
    reschedule_domain(domain)       # in each worker's finally, after processing
    periodically: cleanup_old_domains(); save_statistics()
```

`process_domain()` and all its error handling are reused unchanged — the queue only
changes *which* domains are selected and *that they are leased and rescheduled*.

## Configuration (env)

| Var                              | Default | Meaning                                   |
| -------------------------------- | ------- | ----------------------------------------- |
| `VMCRAWL_QUEUE_MODE`             | `false` | Opt in to the durable queue daemon        |
| `VMCRAWL_QUEUE_BATCH`            | `100`   | Domains claimed per round                 |
| `VMCRAWL_QUEUE_LEASE_SECONDS`    | `900`   | Lease TTL before a claim is reclaimable   |
| `VMCRAWL_QUEUE_POLL_SECONDS`     | `15`    | Sleep when nothing is due                 |
| `VMCRAWL_RECRAWL_HOURS`          | `1`     | Healthy Mastodon recrawl cadence          |
| `VMCRAWL_RECRAWL_NONMASTO_HOURS` | `168`   | Known non-Mastodon recrawl cadence (7d)   |
| `VMCRAWL_RETRY_CAP_HOURS`        | `720`   | Backoff ceiling for transient types (30d) |
| `VMCRAWL_RETRY_HTTP5XX_HOURS`    | `6`     | Per-type base: 5xx (recovers fast)        |
| `VMCRAWL_RETRY_TCP_HOURS`        | `12`    | Per-type base: TCP                        |
| `VMCRAWL_RETRY_DNS_HOURS`        | `24`    | Per-type base: DNS                        |
| `VMCRAWL_RETRY_SSL_HOURS`        | `24`    | Per-type base: SSL                        |
| `VMCRAWL_RETRY_CONTENT_HOURS`    | `24`    | Per-type base: TYPE/FILE/JSON/API         |
| `VMCRAWL_RETRY_HTTP2XX_HOURS`    | `48`    | Per-type base: unexpected 2xx             |
| `VMCRAWL_RETRY_HTTP3XX_HOURS`    | `48`    | Per-type base: redirect                   |
| `VMCRAWL_RETRY_HTTP4XX_HOURS`    | `48`    | Per-type base: 4xx                        |
| `VMCRAWL_RETRY_ROBOT_HOURS`      | `720`   | Per-type base: robots disallow (flat 30d) |
| `VMCRAWL_RETRY_HARD_HOURS`       | `2160`  | Per-type base: gone 410/451/418/999 (90d) |

## Rollout

1. Apply `database.sql` (idempotent — adds queue columns, **drops the obsolete
   `bad_*` columns/indexes**, adds the reason index, backfill).
2. Deploy code; queue daemon stays **off** by default.
3. Turn on for one worker via `VMCRAWL_QUEUE_MODE=true`; watch `claimed_by`,
   `next_crawl_at` distribution, and throughput.
4. Once happy, make it the default headless path and retire the whole-batch re-select.

The reason-based menu/batch/retry tooling (options 4/5/20–32) keeps working
throughout — it reads and writes the same `raw_domains` rows, just without lease
discipline. The old `bad_*`-based retry menu (60–72) is removed; options 20–32
cover the same classifications via `reason`.
