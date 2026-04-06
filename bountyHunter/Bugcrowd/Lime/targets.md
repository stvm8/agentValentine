---
tags: [bugbounty, p1_to_p4, lime, bugcrowd]
date: 2026-04-02
---

# Lime Bug Bounty — admintool.lime.bike

## Stack
- Frontend: Vite SPA, React, MUI, @limebike/supreme
- CDN/WAF: Cloudflare + Bot Management
- Backend: AWS (origin)
- Auth: Lime Account (email/phone) + Google OAuth (GSI)
- Analytics: Amplitude, DataDog RUM (env:production, service:admintool, ver:fe0edbb)

## API Base
`https://admintool.lime.bike/api/`

## Confirmed API Endpoints (op/v1)
### Auth
- POST `op/v1/login_google`
- POST `op/v1/logout`

### Operators (HIGH PRIORITY — IDOR candidates)
- GET  `op/v1/operators`
- GET  `op/v1/operators/me`          [tested: 401]
- GET  `op/v1/operators/<id>`
- POST `op/v1/operators/<id>/deactivate`
- GET  `op/v1/operators/location_history`
- GET  `op/v1/operators/map_index`
- POST `op/v1/operators/reset-password-email`

### Permissions (PRIVILEGE ESCALATION targets)
- GET/POST `op/v1/permission_requests`
- GET      `op/v1/permission_requests/fetch_approvers`
- GET      `op/v1/permission_policies`

### Pricing (BUSINESS LOGIC targets)
- GET/POST `op/v1/zone_pricing_configs?zone_id=<id>`
- POST     `op/v1/zone_pricing_configs/update`
- GET      `op/v1/pricing_experiments/region_pricing_or_experiments?region_id=<id>`

### Regions
- GET/POST `op/v1/regions`
- GET      `op/v1/regions/default_region`
- GET      `op/v1/regions/download_region`
- GET      `op/v1/regions/region_settings`
- GET      `op/v1/regions/<id>`
- POST     `op/v1/regions/<id>/enable_feature`
- POST     `op/v1/regions/<id>/disable_feature`
- POST     `op/v1/regions/<id>/set_speed_limit`
- POST     `op/v1/regions/<id>/region_pricing_configs`
- GET      `op/v1/regions/<id>/subregion_pricing_configs`

## Hardcoded Secrets/Keys
- Google Maps API Key: `AIzaSyDXwtpX5C1Z8Ck6xMhYwv1ESEIBD5zoXZI`
- Cloudflare Turnstile Site Key: `0x4AAAAAAAUqzE4z3Ao2BXyN`
- Google OAuth Client IDs:
  - `204201963357-ns8pa1flbj0lpqk074r57k37sn957eat.apps.googleusercontent.com`
  - `63320634379-rdesh0vqf8pidm4godpqh7fduee4va7r.apps.googleusercontent.com`
  - `726243844022-q5314sk0teplamajn2v8pd6b84llni10.apps.googleusercontent.com`

## Other Internal Assets (from JS bundle)
- `admintool-staging.lime.bike` (OUT OF SCOPE)
- `data.limeinternal.com` (IN SCOPE)
- `tab.limeinternal.com` (NOT in ROE — do not test)

## Attack Vectors (Priority Order)
1. Auth bypass / Google OAuth misconfiguration (any Google account?)
2. Unauthenticated API endpoint enumeration (BOLA/IDOR pre-auth)
3. Post-auth IDOR on `/operators/<id>`
4. Permission escalation via `/permission_requests`
5. Google Maps API key scope abuse
