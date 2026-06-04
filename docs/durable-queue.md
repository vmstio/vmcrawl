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
  menu choice (options 4/5/20–32/60–72). There is no automatic backoff.

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
not stampede every row at once (uncrawled → due now; terminal → spread over the dead
interval; everything else → spread over the recrawl interval).

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
            AND strpos(raw_domains.domain, d.domain) > 0
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
- **Known failure domains are still claimed and recrawled.** Every terminal
  `bad_*` state — DNS, TCP, SSL, … *and* `bad_hard` (the permanent "gone" codes
  HTTP 410/451/418/999) — is claimed once it comes due and actually re-attempted,
  rather than being excluded from the queue. They revive on the long dead
  interval (default 30d, see *Reschedule policy*) so they are retried periodically
  rather than hammered.
- **The worker skips no domain on its recorded state in queue mode**
  (`bypass_skip_filters=True`), because the claim query above is the
  authoritative filter — every domain it hands back is meant to be (re)crawled.
  Without this, a revived failure domain or a re-claimed not-Mastodon domain
  would be claimed only to be skipped by the in-process state filter and
  rescheduled untouched, silently defeating both the failure revival and
  migration re-detection. The only permanent exclusions left are aliases and
  hard-DNI.
- **Hard-DNI domains are never claimed.** The `NOT EXISTS` clause mirrors the
  worker-side substring match in `_is_dni_domain` (`any(dni in domain)`) using
  `strpos`, so a `dni` entry with `force = 'hard'` that is a substring of the domain
  keeps it out of the queue entirely. (Soft-DNI is recorded but not enforced, matching
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
deriving the interval from the row's *resulting* state — so it is correct regardless
of which Python code path set the flags:

```text
next_crawl_at = now() + CASE
    WHEN bad_hard OR bad_robot           THEN dead_interval      -- immediate-terminal
    WHEN (any bad_* = TRUE)              THEN dead_interval      -- error buffer exceeded
    WHEN reason IS NOT NULL              THEN backoff(attempts)  -- transient failure
    WHEN nodeinfo IS NOT NULL
         AND nodeinfo NOT IN (masto set) THEN nonmasto_interval  -- known non-Mastodon
    ELSE                                      recrawl_interval   -- healthy
END
attempts = CASE WHEN reason IS NOT NULL THEN attempts + 1 ELSE 0 END
claimed_at = NULL, claimed_by = NULL
```

`backoff(attempts) = least(2^attempts * retry_base, retry_cap)` (old `attempts` used
as the exponent, then incremented), bounded exponential — analogous to
joinmastodon-api's `min(error_count**3 hours, 30.days)`.

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
| `VMCRAWL_RETRY_BASE_HOURS`       | `1`     | Transient backoff base                    |
| `VMCRAWL_RETRY_CAP_HOURS`        | `168`   | Transient backoff cap (7d)                |
| `VMCRAWL_DEAD_HOURS`             | `720`   | Terminal/dead recrawl cadence (30d)       |

## Rollout

1. Apply `database.sql` (idempotent — adds columns, index, backfill).
2. Deploy code; queue daemon stays **off** by default.
3. Turn on for one worker via `VMCRAWL_QUEUE_MODE=true`; watch `claimed_by`,
   `next_crawl_at` distribution, and throughput.
4. Once happy, make it the default headless path and retire the whole-batch re-select.

The existing menu/batch/retry tooling keeps working throughout — it reads and writes
the same `raw_domains` rows, just without lease discipline.
