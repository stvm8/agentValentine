# High-Value Targets — JustEatTakeaway (Bugcrowd)

## LIVE AUTH-GATED ENDPOINTS (uk.api.just-eat.io)
| Status | Endpoint | Auth Required | Priority |
|--------|----------|---------------|----------|
| 401 | /consumer/me/orders/uk | Bearer JWT | ★★★ IDOR Candidate |
| 401 | /delivery/pools | X-Flyt-Api-Key | ★★ Partner API |
| 401 | /delivery/pools/{id} | X-Flyt-Api-Key | ★★ |
| 401 | /delivery/pools/{id}/availability/relative | X-Flyt-Api-Key | ★★ |
| 401 | /delivery/pools/{id}/status | X-Flyt-Api-Key | ★★ |

## SECONDARY API TARGETS
| Target | Known Issues | Notes |
|--------|--------------|-------|
| rest.api.eu-central-1.production.jet-external.com | 3 | Same codebase |
| cw-api.takeaway.com | 1 | |
| api.justeat-int.com | 1 | Integration/staging — likely weaker auth |
| aus.api.just-eat.io | 0 | Same codebase, AU region |

## GITHUB
| Target | Notes |
|--------|-------|
| github.com/justeattakeaway | IN SCOPE — potential leaked keys/configs |

## AUTH SCHEMES (from OpenAPI spec)
- Consumer: `Authorization: Bearer <JWT>` — get by registering at just-eat.co.uk with @bugcrowdninja.com email
- Partner: `Authorization: JE-API-KEY <key>` — for uk-partnerapi.just-eat.io
- DaaS: `X-Flyt-Api-Key: <key>` — delivery pool endpoints

## WAF
- Cloudflare active on uk.api.just-eat.io
- Rate limit: 10,000 req/s (header confirmed)
- SQLi keyword paths (char(), concat()) return 403
