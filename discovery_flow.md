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
                    │ save_nodeinfo_      │  │ STOP/RETURN  │
                    │ software()          │  │ (bad data)   │
                    │ Save platform name  │  └──────────────┘
                    └──────────┬──────────┘
                               │
                   ┌───────────▼────────────┐
                   │ is_mastodon_instance?  │
                   └───────────┬────────────┘
                               │
                   ┌───────────┴────────────┐
                   │                        │
                 YES│                       │NO
                   │                        │
                   ▼                        ▼
       ┌──────────────────────┐  ┌──────────────────────┐
       │ process_mastodon_    │  │ mark_as_non_mastodon │
       │ instance()           │  │ delete_domain_if_    │
       └──────────┬───────────┘  │ known()              │
                  │              │ (Lemmy, Pixelfed,    │
                  ▼              │  etc.)               │
       ┌──────────────────────┐  └──────────┬───────────┘
       │ get_instance_uri()   │             │
       │ /api/v1/instance     │             │
       └──────────┬───────────┘             │
                  │                         │
       ┌──────────▼───────────┐             │
       │ Instance URI found?  │             │
       └──────────┬───────────┘             │
                  │                         │
       ┌──────────┴───────────┐             │
       │                      │             │
    YES│                      │NO           │
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
│ STOP/  │  │ Validate       │              │
│ RETURN │  │ version        │              │
│ (alias)│  └──────┬─────────┘              │
│ Mark   │         │                        │
│ domain │         ▼                        │
│ as     │  ┌────────────────┐              │
│ alias  │  │ Save to        │              │
└────────┘  │ mastodon_      │              │
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
2. Mark domain with `alias = TRUE` in `raw_domains` table
3. Delete domain from `mastodon_domains` if present
4. Stop processing immediately

### Skip Processing

Domains marked as aliases are skipped during processing:
- Loaded at startup via `get_alias_domains()`
- Checked in `should_skip_domain()`
- Always skipped (no user override option)
- Log message: `"{domain}: Alias Domain"` (cyan)

## Error Handling

- **robots.txt blocks**: Stop immediately, mark as norobots
- **Host-meta fails**: Continue to webfinger (silent, no logging)
- **Webfinger fails**: Continue to nodeinfo with original domain (silent, no logging)
- **NodeInfo fails**: Stop, log error, increment error counter (ONLY logged failure)
- **Non-Mastodon detected**: Mark and skip (not an error)
- **Alias detected**: Stop, mark as alias, skip in future runs

### Why Silent Failures?

Host-meta and webfinger are **discovery mechanisms** - their failure doesn't mean the domain is broken, just that we need to try another method. Only when **all** methods fail (nodeinfo returns nothing) do we log it as an actual error.
