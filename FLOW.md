# Domain Discovery Flow Chart

```
┌─────────────────────────────────────────────────────────────────────┐
│                          START: process_domain                      │
│                             (domain input)                          │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  check_robots_txt()    │
                    │  Verify crawling OK    │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Allowed to crawl?    │
                    └───────────┬────────────┘
                                │
                    ┌───────────┴────────────┐
                    │                        │
                  NO│                        │YES
                    │                        │
                    ▼                        ▼
            ┌──────────────┐    ┌────────────────────────────────────┐
            │  STOP/RETURN │    │  check_nodeinfo() at original     │
            │  (bad_robot) │    │  domain (suppress_errors=True)     │
            └──────────────┘    │  Probe for nodeinfo directly       │
                                └───────────────────┬────────────────┘
                                                    │
                                        ┌───────────▼────────────┐
                                        │ NodeInfo found at      │
                                        │ original domain?       │
                                        └───────────┬────────────┘
                                                    │
                                        ┌───────────┴────────────┐
                                        │                        │
                                     YES│                        │NO
                                        │                        │
                                        │                        ▼
                                        │           ┌────────────────────────────────┐
                                        │           │ discover_backend_domain_       │
                                        │           │ parallel()                     │
                                        │           │ Run host-meta & webfinger in   │
                                        │           │ parallel via asyncio.gather()  │
                                        │           └───────────────┬────────────────┘
                                        │                           │
                                        │               ┌───────────▼────────────┐
                                        │               │ Backend discovered?    │
                                        │               └───────────┬────────────┘
                                        │                           │
                                        │               ┌───────────┴────────────┐
                                        │               │                        │
                                        │            YES│                        │NO (fallback)
                                        │               │                        │
                                        │               ▼                        ▼
                                        │   ┌─────────────────────┐  ┌──────────────────┐
                                        │   │ check_nodeinfo()    │  │ STOP/RETURN      │
                                        │   │ at backend_domain   │  │ Replay suppressed│
                                        │   └──────────┬──────────┘  │ probe error      │
                                        │              │             └──────────────────┘
                                        │   ┌──────────▼──────────┐
                                        │   │ NodeInfo found?     │
                                        │   └──────────┬──────────┘
                                        │              │
                                        │   ┌──────────┴──────────┐
                                        │   │                     │
                                        │ YES                     │NO
                                        │   │                     │
                                        │   │                     ▼
                                        │   │          ┌──────────────┐
                                        │   │          │ STOP/RETURN  │
                                        │   │          │ (no nodeinfo)│
                                        │   │          └──────────────┘
                                        │   │
                                        ▼   ▼
                                ┌────────────────────────┐
                                │ NodeInfo data returned  │
                                │ directly at well-known? │
                                └───────────┬─────────────┘
                                            │
                                ┌───────────┴────────────┐
                                │                        │
                             YES│                        │NO
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────┐  ┌────────────────────┐
                    │ Use nodeinfo_20_    │  │ check_nodeinfo_20()│
                    │ data directly       │  │ Fetch platform info│
                    │ (skip fetch)        │  │ from nodeinfo URL  │
                    └──────────┬──────────┘  └──────────┬─────────┘
                               │                        │
                               └────────┬───────────────┘
                                        │
                                ┌───────▼────────────────┐
                                │ NodeInfo data valid?   │
                                └───────────┬────────────┘
                                            │
                                ┌───────────┴────────────┐
                                │                        │
                             YES│                        │NO
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────┐  ┌──────────────┐
                    │ _is_mastodon_       │  │ STOP/RETURN  │
                    │ instance()?         │  │ (bad data)   │
                    └──────────┬──────────┘  └──────────────┘
                               │
                   ┌───────────┴────────────┐
                   │                        │
                YES│                        │NO
                   │                        │
                   ▼                        ▼
       ┌──────────────────────┐  ┌──────────────────────┐
       │ get_instance_uri()   │  │ save_nodeinfo_       │
       │ Try v2 API first     │  │ software()           │
       │ /api/v2/instance     │  │ Save platform name   │
       │ (domain field)       │  │ to nodeinfo column   │
       │ Fallback to v1 API   │  │                      │
       │ /api/v1/instance     │  │ mark_as_non_mastodon │
       │ (uri field)          │  │ delete_domain_if_    │
       └──────────┬───────────┘  │ known()              │
                  │              │ (Lemmy, Pixelfed,    │
       ┌──────────▼───────────┐  │  etc.)               │
       │ Returns 401?         │  └──────────┬───────────┘
       └──────────┬───────────┘             │
                  │                         │
       ┌──────────┴───────────┐             │
       │                      │             │
    YES│                      │NO           │
       │                      │             │
       ▼                      ▼             │
┌────────────────┐  ┌──────────────────┐   │
│ STOP/RETURN    │  │ Instance URI     │   │
│ (bad_api)      │  │ found?           │   │
│ Record API     │  └──────────┬───────┘   │
│ error          │             │           │
│                │  ┌──────────┴───────┐   │
└────────────────┘  │                  │   │
                 YES│                  │NO  │
                    │                  │   │
                    ▼                  ▼   │
         ┌────────────────┐  ┌──────────────┐
         │ save_nodeinfo_ │  │ STOP/RETURN  │
         │ software()     │  │ (no instance │
         │                │  │  URI)        │
         │ process_       │  │ Record API   │
         │ mastodon_      │  │ error        │
         │ instance()     │  └──────────────┘
         └──────┬─────────┘             │
                │                       │
                ▼                       │
┌────────────────────────┐              │
│ actual_domain differs  │              │
│ from original domain?  │              │
└──────────┬─────────────┘              │
           │                            │
   ┌───────┴────────┐                   │
   │                │                   │
  YES               │NO                │
   │                │                   │
   ▼                ▼                   │
┌────────────┐  ┌────────────────┐      │
│ Mark       │  │ Validate       │      │
│ original   │  │ version and    │      │
│ domain as  │  │ MAU data       │      │
│ alias via  │  │                │      │
│ mark_      │  │ Save to        │      │
│ domain_as_ │  │ mastodon_      │      │
│ alias()    │  │ domains table  │      │
│            │  │                │      │
│ Delete     │  │ clear_domain_  │      │
│ from known │  │ error()        │      │
│ domains    │  └──────┬─────────┘      │
└──────┬─────┘         │               │
       │               │               │
       └───────────────┴───────┬───────┘
                               │
                               ▼
                       ┌───────────────┐
                       │  END/RETURN   │
                       └───────────────┘
```

## Nodeinfo Probe-First Strategy

The crawler uses a **probe-first** approach to minimize unnecessary HTTP requests:

1. **Probe**: Try `check_nodeinfo()` at the original domain with `suppress_errors=True`
2. **If probe succeeds**: Skip backend discovery entirely (saves 2+ HTTP requests)
3. **If probe fails**: Run backend discovery, then retry nodeinfo at the discovered backend
4. **If both fail**: Replay the suppressed probe error for proper error tracking

This optimization avoids host-meta and webfinger requests for domains that serve nodeinfo directly, which is the common case.

### Suppressed Error Handling

When the nodeinfo probe fails with `suppress_errors=True`:
- Errors are captured but not logged or counted
- If backend discovery finds a different host, the probe error is discarded
- If backend discovery also fails (fallback), the original probe error is **replayed** through the normal error handlers
- This prevents double-counting errors while still tracking failures accurately

## Discovery Methods (Parallel Execution)

Backend domain discovery runs **host-meta** and **webfinger** in parallel using `asyncio.gather()`. The first successful result is used based on priority order.

### 1. **host-meta** (Highest Priority)
- **URL**: `https://domain/.well-known/host-meta`
- **Format**: XML
- **Returns**: Backend domain from webfinger template
- **Example**: vivaldi.net → social.vivaldi.net

### 2. **webfinger** (Second Priority)
- **URL**: `https://domain/.well-known/webfinger?resource=acct:domain@domain`
- **Format**: JSON
- **Returns**: Backend domain from aliases array
- **Example**: mastodon.social → mastodon.social (same)

### 3. **Fallback**
- If both methods fail, the original domain is used (triggers error replay)

### 4. **nodeinfo** (Required - Platform Identification)
- **URL**: `https://backend_domain/.well-known/nodeinfo`
- **Format**: JSON
- **Returns**: NodeInfo 2.0 URL, or nodeinfo data directly
- **Then fetches**: NodeInfo data with software.name (unless data was returned directly)
- **Purpose**: Identify if Mastodon or other platform
- **Special cases**:
  - **Matrix detection**: If response contains `m.server` field, domain is marked as `matrix` in nodeinfo and processing stops
  - **Direct data return**: Some servers return full nodeinfo data at the well-known endpoint instead of a links document; this is handled transparently
  - **Backend extraction**: The hostname from the nodeinfo_20_url may differ from the backend_domain; if so, `backend_domain` is updated for the instance API call

### 5. **instance API** (Required for Mastodon - Domain Validation)
- **Primary URL**: `https://backend_domain/api/v2/instance`
- **Fallback URL**: `https://backend_domain/api/v1/instance`
- **Format**: JSON
- **Returns**: 
  - v2 API: `domain` field (authoritative domain name)
  - v1 API: `uri` field (authoritative domain URI, normalized to bare hostname)
- **Purpose**: Get canonical domain and detect aliases
- **Special Handling**: 
  - **401 Unauthorized**: `API` error recorded via `increment_domain_error`, processing stops
  - **Other errors**: Error recorded via `increment_domain_error`, counter incremented

## Key Decision Points

1. **Nodeinfo Probe**: Tries original domain first to skip backend discovery when possible
2. **Parallel Discovery**: Host-meta and webfinger run concurrently; host-meta result takes priority if available
3. **Discovery Failure**: If probe and both discovery methods fail, suppressed probe error is replayed
4. **NodeInfo Result**: Determines Mastodon vs non-Mastodon handling
5. **Software Name**: Final classification (mastodon, lemmy, pixelfed, matrix, etc.)
6. **Software Data Timing**: 
   - For **Mastodon instances**: `save_nodeinfo_software()` is called after instance URI is retrieved, then `process_mastodon_instance()` handles alias detection, version validation, and MAU extraction
   - For **non-Mastodon platforms**: `save_nodeinfo_software()` is called unconditionally, saving the platform name to `nodeinfo` column in `raw_domains`

## Alias Detection

After successfully identifying a Mastodon instance and retrieving its instance URI, the crawler checks if the domain is an **alias** (redirect) to another instance.

### Alias Logic

A domain is marked as an alias when:
- The `actual_domain` (from instance URI) differs from the original `domain`

The alias check occurs inside `process_mastodon_instance()` after all validation and database updates for the canonical domain are complete.

### Examples

**Not Aliases (Valid)**:
- `example.com` → `example.com` (same domain)

**Aliases (Marked and skipped)**:
- `example.com` → `other.com` (different domain)
- `social.example.com` → `example.com` (redirect to parent)
- `alias.com` → `main-instance.org` (completely different)

### Alias Handling

When an alias is detected (`actual_domain != domain`):
1. Version and MAU data are saved under the **canonical** domain (`actual_domain`)
2. The original domain is marked as alias via `mark_domain_as_alias(domain)`, which:
   - Sets `alias = TRUE` in `raw_domains`
   - Clears all state columns: `errors`, `reason`, `nodeinfo`, and all `bad_*` flags
3. The original domain is deleted from `mastodon_domains` via `delete_domain_if_known(domain)`

### Skip Processing

Domains marked with certain flags are skipped during processing in `_should_skip_domain()`:

**Non-Mastodon domains**:
- Loaded at startup via `get_not_masto_domains()`
- Skipped unless user selects option "10" (Retry Non-Mastodon)
- Log message: `"{domain}: Other Platform"` (cyan)

**Bad domains** (terminal error states):
- Loaded at startup via `get_all_bad_domains()` which returns a dict of `{column: set_of_domains}` for all `bad_*` columns
- Checked in `_should_skip_domain()` by iterating `bad_domain_sets`
- Skipped unless user selects the corresponding retry option (menu choices 60-73)
- Log message: `"{domain}: {label}"` (cyan)

**DNI and invalid TLD domains**:
- Checked in `_is_dni_or_invalid_tld()` after the skip check
- DNI domains are matched by substring (any DNI domain contained in the domain string)
- Invalid TLDs are checked against a pre-computed suffix set
- Both are purged from `raw_domains` and `mastodon_domains`

## Error Handling

- **robots.txt blocks**: Stop immediately, record `ROBOT` error via `increment_domain_error`
- **NodeInfo probe fails**: Error suppressed; replayed only if backend discovery also fails
- **Host-meta fails**: Silent (parallel discovery fallback)
- **Webfinger fails**: Silent (parallel discovery fallback)
- **NodeInfo fails at backend**: Stop, log error, increment error counter
- **Matrix detected**: Mark as `matrix` in nodeinfo, clear errors, stop processing (not an error)
- **Non-Mastodon detected**: Save software name to `nodeinfo` column, clear errors, mark and skip (not an error)
- **Instance API returns 401**: Stop immediately, record `API` error via `increment_domain_error`
- **Instance API fails**: Stop, record `API` error via `increment_domain_error`
- **HTTP 410/418/451/999**: Record `HARD` error via `increment_domain_error` (immediately terminal)
- **Version invalid**: Record `VER` error, delete from known domains
- **MAU data missing**: Record `MAU` error, delete from known domains
- **Alias detected**: Mark as alias via `mark_domain_as_alias()`, delete original from known domains

All errors route through `increment_domain_error`, which tracks consecutive same-type errors and sets the corresponding `bad_*` column after 8 consecutive failures. `ROBOT` and `HARD` error types are immediately terminal on first occurrence.

### Why Silent Failures?

Host-meta and webfinger are **discovery mechanisms** that run in parallel - their individual failures don't mean the domain is broken. The parallel execution via `asyncio.gather()` collects both results, and priority resolution picks the best available. The nodeinfo probe uses `suppress_errors=True` so that probe failures at the original domain don't count against the domain when a backend host is successfully discovered.

### Software Data Storage

The `save_nodeinfo_software()` function stores the platform name from NodeInfo to the `raw_domains.nodeinfo` column:

- **For Mastodon instances**: Software data is saved after the instance URI is successfully retrieved, before `process_mastodon_instance()` runs. Inside `process_mastodon_instance()`:
  1. Version is cleaned and validated
  2. MAU data is extracted and validated
  3. Data is saved to `mastodon_domains` under the canonical domain (`actual_domain`)
  4. If `actual_domain != domain`, the original domain is marked as alias
  
- **For non-Mastodon platforms**: Software data is saved unconditionally
  - Platforms like Lemmy, Pixelfed, Misskey, etc. are saved immediately
  - Non-Mastodon platforms also have their `errors` and `reason` fields cleared since being a different platform is not an error condition
