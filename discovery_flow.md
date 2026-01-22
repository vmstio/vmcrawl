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
            ┌──────────────┐    ┌────────────────────────┐
            │  STOP/RETURN │    │  check_host_meta()     │
            │  (norobots)  │    │  Try XML discovery     │
            └──────────────┘    └───────────┬────────────┘
                                            │
                                ┌───────────▼────────────┐
                                │ Backend domain found?  │
                                └───────────┬────────────┘
                                            │
                                ┌───────────┴────────────┐
                                │                        │
                             YES│                        │NO
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────┐  ┌────────────────────────┐
                    │ Use host-meta       │  │  check_webfinger()     │
                    │ backend_domain      │  │  Try JSON discovery    │
                    │ (skip webfinger)    │  └───────────┬────────────┘
                    └──────────┬──────────┘              │
                               │             ┌───────────▼────────────┐
                               │             │ Backend domain found?  │
                               │             └───────────┬────────────┘
                               │                         │
                               │             ┌───────────┴────────────┐
                               │             │                        │
                               │          YES│                        │NO
                               │             │                        │
                               │             ▼                        ▼
                               │  ┌────────────────────┐  ┌────────────────────┐
                               │  │ Use webfinger      │  │ Use original       │
                               │  │ backend_domain     │  │ domain as fallback │
                               │  │ (from aliases)     │  │ (last resort)      │
                               │  └──────────┬─────────┘  └──────────┬─────────┘
                               │             │                       │
                               └─────────────┴───────────┬───────────┘
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
       │ /api/v1/instance     │  │ software()           │
       └──────────┬───────────┘  │ Save platform name   │
                  │              │ to nodeinfo column   │
       ┌──────────▼───────────┐  │                      │
       │ Instance URI found?  │  │ mark_as_non_mastodon │
       └──────────┬───────────┘  │ delete_domain_if_    │
                  │              │ known()              │
       ┌──────────┴───────────┐  │ (Lemmy, Pixelfed,    │
       │                      │  │  etc.)               │
    YES│                      │NO└──────────┬───────────┘
       │                      │             │
       ▼                      ▼             │
┌────────────────┐  ┌──────────────┐        │
│ Use actual_    │  │ STOP/RETURN  │        │
│ domain from    │  │ (no instance │        │
│ instance URI   │  │  URI)        │        │
└──────┬─────────┘  └──────────────┘        │
       │                                    │
       ▼                                    │
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

## Discovery Methods (Priority Order)

### 1. **host-meta** (Preferred - Fast)
- **URL**: `https://domain/.well-known/host-meta`
- **Format**: XML
- **Returns**: Backend domain from webfinger template
- **Example**: vivaldi.net → social.vivaldi.net
- **On Failure**: Falls back to webfinger

### 2. **webfinger** (Fallback - Standard)
- **URL**: `https://domain/.well-known/webfinger?resource=acct:domain@domain`
- **Format**: JSON
- **Returns**: Backend domain from aliases array
- **Example**: mastodon.social → mastodon.social (same)
- **On Failure**: Uses original domain

### 3. **nodeinfo** (Required - Platform Identification)
- **URL**: `https://backend_domain/.well-known/nodeinfo`
- **Format**: JSON
- **Returns**: NodeInfo 2.0 URL
- **Then fetches**: NodeInfo data with software.name
- **Purpose**: Identify if Mastodon or other platform

## Key Decision Points

1. **Host-meta Success**: Skip webfinger entirely (optimization)
2. **Webfinger Failure**: Use original domain (graceful degradation)
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

Domains marked as aliases are skipped during processing:
- Loaded at startup via `get_alias_domains()`
- Checked in `should_skip_domain()`
- Always skipped (no user override option)
- Log message: `"{domain}: Alias Domain"` (cyan)

## Error Handling

- **robots.txt blocks**: Stop immediately, mark as norobots using `mark_domain_status(domain, "norobots")`
- **Host-meta fails**: Continue to webfinger (silent, no logging)
- **Webfinger fails**: Continue to nodeinfo with original domain (silent, no logging)
- **NodeInfo fails**: Stop, log error, increment error counter (ONLY logged failure)
- **Non-Mastodon detected**: Save software name to `nodeinfo` column, mark and skip (not an error)
- **Alias detected**: Stop, mark as alias using `mark_domain_status(domain, "alias")`, skip in future runs

### Why Silent Failures?

Host-meta and webfinger are **discovery mechanisms** - their failure doesn't mean the domain is broken, just that we need to try another method. Only when **all** methods fail (nodeinfo returns nothing) do we log it as an actual error.

### Software Data Storage

The `save_nodeinfo_software()` function stores the platform name from NodeInfo to the `raw_domains.nodeinfo` column:

- **For Mastodon instances**: Software data is saved ONLY after:
  1. Instance URI is successfully retrieved
  2. Domain is verified to NOT be an alias
  3. This prevents saving "mastodon" for domains that redirect elsewhere
  
- **For non-Mastodon platforms**: Software data is saved unconditionally
  - Platforms like Lemmy, Pixelfed, Misskey, etc. are saved immediately
  - Non-Mastodon platforms also have their `errors` and `reason` fields cleared since being a different platform is not an error condition
