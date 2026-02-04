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
            │  STOP/RETURN │    │  discover_backend_domain_parallel()│
            │  (norobots)  │    │  Run host-meta & webfinger in      │
            └──────────────┘    │  parallel via asyncio.gather()     │
                                └───────────────────┬────────────────┘
                                                    │
                                        ┌───────────▼────────────┐
                                        │ Priority resolution:   │
                                        │ 1. host-meta result    │
                                        │ 2. webfinger result    │
                                        │ 3. original domain     │
                                        └───────────┬────────────┘
                                                    │
                                             ┌───────────▼────────────┐
                                             │ check_nodeinfo()       │
                                             │ at backend_domain      │
                                             └───────────┬────────────┘
                                                         │
                                             ┌───────────▼────────────┐
                                             │ NodeInfo URL found?    │
                                             └───────────┬────────────┘
                                                         │
                                             ┌───────────┴────────────┐
                                             │                        │
                                          YES│                        │NO
                                             │                        │
                                             ▼                        ▼
                                 ┌────────────────────┐   ┌──────────────┐
                                 │ check_nodeinfo_20()│   │ STOP/RETURN  │
                                 │ Fetch platform info│   │ (no nodeinfo)│
                                 └──────────┬─────────┘   └──────────────┘
                                            │
                                ┌───────────▼────────────┐
                                │ NodeInfo data valid?   │
                                └───────────┬────────────┘
                                            │
                                ┌───────────┴────────────┐
                                │                        │
                             YES│                        │NO
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────┐  ┌──────────────┐
                    │ is_mastodon_        │  │ STOP/RETURN  │
                    │ instance?           │  │ (bad data)   │
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
│ (noapi)        │  │ found?           │   │
│ Mark domain as │  └──────────┬───────┘   │
│ noapi, delete  │             │           │
│ from known     │  ┌──────────┴───────┐   │
│ domains        │  │                  │   │
└────────────────┘  │               YES│NO │
                 YES│                  │   │
                    ▼                  ▼   │
         ┌────────────────┐  ┌──────────────┐
         │ Use actual_    │  │ STOP/RETURN  │
         │ domain from    │  │ (no instance │
         │ instance URI   │  │  URI)        │
         └──────┬─────────┘  └──────────────┘
                │                           │
                │                           │
                ▼                           │
┌────────────────┐                          │
│ is_alias_      │                          │
│ domain()?      │                          │
│ Check if URI   │                          │
│ differs from   │                          │
│ domain         │                          │
└──────┬─────────┘                          │
       │                                    │
   ┌───┴────┐                               │
   │        │                               │
YES│        │NO                             │
   │        │                               │
   ▼        ▼                               │
┌────────┐  ┌────────────────┐              │
│ STOP/  │  │ save_nodeinfo_ │              │
│ RETURN │  │ software()     │              │
│ (alias)│  │ Save platform  │              │
│ Mark   │  │ name to        │              │
│ domain │  │ nodeinfo column│              │
│ as     │  │                │              │
│ alias  │  │ Validate       │              │
└────────┘  │ version        │              │
            │                │              │
            │ Save to        │              │
            │ mastodon_      │              │
            │ domains table  │              │
            └──────┬─────────┘              │
                   │                        │
                   └────────────┬───────────┘
                                │
                                ▼
                        ┌───────────────┐
                        │  END/RETURN   │
                        └───────────────┘
```

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
- If both methods fail, the original domain is used

### 4. **nodeinfo** (Required - Platform Identification)
- **URL**: `https://backend_domain/.well-known/nodeinfo`
- **Format**: JSON
- **Returns**: NodeInfo 2.0 URL
- **Then fetches**: NodeInfo data with software.name
- **Purpose**: Identify if Mastodon or other platform

### 5. **instance API** (Required for Mastodon - Domain Validation)
- **Primary URL**: `https://backend_domain/api/v2/instance`
- **Fallback URL**: `https://backend_domain/api/v1/instance`
- **Format**: JSON
- **Returns**: 
  - v2 API: `domain` field (authoritative domain name)
  - v1 API: `uri` field (authoritative domain URI)
- **Purpose**: Get canonical domain and detect aliases
- **Special Handling**: 
  - **401 Unauthorized**: Domain marked as `noapi = TRUE`, processing stops
  - **Other errors**: Domain marked with error reason, error counter incremented

## Key Decision Points

1. **Parallel Discovery**: Host-meta and webfinger run concurrently; host-meta result takes priority if available
2. **Discovery Failure**: If both methods fail, original domain is used (graceful degradation)
3. **NodeInfo Result**: Determines Mastodon vs non-Mastodon handling
4. **Software Name**: Final classification (mastodon, lemmy, pixelfed, etc.)
5. **Software Data Timing**: 
   - For **Mastodon instances**: Saved only after validation and alias check (prevents saving data for aliases)
   - For **non-Mastodon platforms**: Saved unconditionally to `nodeinfo` column in `raw_domains`

## Alias Detection

After successfully identifying a Mastodon instance and retrieving its instance URI, the crawler checks if the domain is an **alias** (redirect) to another instance.

### Alias Logic

A domain is marked as an alias when:
- The instance URI differs from the original domain
- The instance URI is **not** a subdomain of the original domain

### Examples

**Not Aliases (Valid)**:
- `example.com` → `example.com` (same domain)
- `example.com` → `social.example.com` (subdomain allowed)

**Aliases (Marked and skipped)**:
- `example.com` → `other.com` (different root domain)
- `social.example.com` → `example.com` (redirect to parent)
- `alias.com` → `main-instance.org` (completely different)

### Alias Handling

When an alias is detected:
1. Log message: `"{domain}: Alias - redirects to {instance_uri}"` (cyan)
2. Mark domain with `alias = TRUE` in `raw_domains` table using `mark_domain_status(domain, "alias")`
3. Delete domain from `mastodon_domains` if present
4. Stop processing immediately (software data is NOT saved for aliases)

### Skip Processing

Domains marked with certain flags are skipped during processing:

**Alias domains**:
- Loaded at startup via `get_alias_domains()`
- Checked in `should_skip_domain()`
- Skipped unless user selects option "16" (Retry Alias)
- Log message: `"{domain}: Alias Domain"` (cyan)

**NoAPI domains** (Instance API requires authentication):
- Loaded at startup via `get_noapi_domains()`
- Checked in `should_skip_domain()`
- Skipped unless user selects option "15" (Retry NoAPI)
- Log message: `"{domain}: API Authentication Required"` (cyan)
- Reason: Instance has restricted their API endpoints with authentication requirements

**NoRobots domains** (Crawling prohibited):
- Loaded at startup via `get_norobots_domains()`
- Checked in `should_skip_domain()`
- Skipped unless user selects option "14" (Retry Prohibited)
- Log message: `"{domain}: Crawling Prohibited"` (cyan)

## Error Handling

- **robots.txt blocks**: Stop immediately, mark as norobots using `mark_domain_status(domain, "norobots")`
- **Host-meta fails**: Continue to webfinger (silent, no logging)
- **Webfinger fails**: Continue to nodeinfo with original domain (silent, no logging)
- **NodeInfo fails**: Stop, log error, increment error counter (ONLY logged failure)
- **Non-Mastodon detected**: Save software name to `nodeinfo` column, mark and skip (not an error)
- **Instance API returns 401**: Stop immediately, mark as noapi using `mark_domain_status(domain, "noapi")`, delete from known domains
- **Alias detected**: Stop, mark as alias using `mark_domain_status(domain, "alias")`, skip in future runs

### Why Silent Failures?

Host-meta and webfinger are **discovery mechanisms** that run in parallel - their individual failures don't mean the domain is broken. The parallel execution via `asyncio.gather()` collects both results, and priority resolution picks the best available. Only when **all** methods fail (nodeinfo returns nothing) do we log it as an actual error.

### Software Data Storage

The `save_nodeinfo_software()` function stores the platform name from NodeInfo to the `raw_domains.nodeinfo` column:

- **For Mastodon instances**: Software data is saved ONLY after:
  1. Instance URI is successfully retrieved
  2. Domain is verified to NOT be an alias
  3. This prevents saving "mastodon" for domains that redirect elsewhere
  
- **For non-Mastodon platforms**: Software data is saved unconditionally
  - Platforms like Lemmy, Pixelfed, Misskey, etc. are saved immediately
  - Non-Mastodon platforms also have their `errors` and `reason` fields cleared since being a different platform is not an error condition
