# Domain Discovery Flow Chart

```
┌─────────────────────────────────────────────────────────────────────┐
│                          START: process_domain                       │
│                             (domain input)                           │
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
                              YES│                       │NO
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
                               │           YES│                       │NO
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
                                           YES│                       │NO
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
                              YES│                       │NO
                                │                        │
                                ▼                        ▼
                    ┌─────────────────────┐  ┌──────────────┐
                    │ save_nodeinfo_      │  │ STOP/RETURN  │
                    │ software()          │  │ (bad data)   │
                    │ Save platform name  │  └──────────────┘
                    └──────────┬──────────┘
                               │
                   ┌───────────▼────────────┐
                   │ is_mastodon_instance? │
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
                  │               │ (Lemmy, Pixelfed,    │
                  ▼               │  etc.)               │
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
     YES│                     │NO           │
       │                      │             │
       ▼                      ▼             │
┌────────────────┐  ┌──────────────┐       │
│ Use actual_    │  │ STOP/RETURN  │       │
│ domain from    │  │ (no instance │       │
│ instance URI   │  │  URI)        │       │
└──────┬─────────┘  └──────────────┘       │
       │                                    │
       ▼                                    │
┌────────────────┐                          │
│ Validate       │                          │
│ version        │                          │
└──────┬─────────┘                          │
       │                                    │
       ▼                                    │
┌────────────────┐                          │
│ Save to        │                          │
│ mastodon_      │                          │
│ domains table  │                          │
└──────┬─────────┘                          │
       │                                    │
       └────────────┬───────────────────────┘
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

## Error Handling

- **robots.txt blocks**: Stop immediately
- **Host-meta fails**: Continue to webfinger (silent)
- **Webfinger fails**: Continue to nodeinfo with original domain
- **NodeInfo fails**: Stop, log error
- **Non-Mastodon detected**: Mark and skip
