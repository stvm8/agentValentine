---
date: 2026-04-03
program: Lime (Bugcrowd)
phase: RECON COMPLETE — Awaiting Auth to Continue
---

# Hunt State

## Targets Tested This Session

### 1. admintool.lime.bike
**Status:** Dead-end for current attack vectors

#### Findings
- **Unauthenticated API:** All endpoints return 401 (operators, regions, permissions, pricing) — properly gated.
- **Google OAuth bypass:** DISPROVED. Client_id `63320634379-...` is `org_internal` in GCP — Google itself rejects non-`@li.me`/`@lime.bike` accounts with error: `"This client is restricted to users within its organization."`
- **Frontend domain whitelist (vde):** `["li.me","ext.li.me","lime.support","team-li.me","support-li.me","city-li.me"]` — frontend-only but backed by Google-level restriction.
- **Google Maps API key:** `AIzaSyDXwtpX5C1Z8Ck6xMhYwv1ESEIBD5zoXZI` — HTTP referrer restricted to `admintool.lime.bike`. Server-side APIs (Geocoding, Directions, Places) all return `REQUEST_DENIED`. Not abusable.
- **`POST op/v1/login_google` payload:** `{email: <string>, user_access_token: <OAuth2 access_token>}` — email is client-controlled but token validation is Google-enforced.

#### OAuth Client IDs (admintool)
| Domain | Client ID |
|---|---|
| li.me, ext.li.me, lime.support (default) | `63320634379-rdesh0vqf8pidm4godpqh7fduee4va7r.apps.googleusercontent.com` |
| team-li.me | `726243844022-q5314sk0teplamajn2v8pd6b84llni10.apps.googleusercontent.com` |
| support-li.me, city-li.me | `204201963357-ns8pa1flbj0lpqk074r57k37sn957eat.apps.googleusercontent.com` |

---

### 2. NEW: data.limeinternal.com — "Lime Data Portal" [HIGH PRIORITY]
**Status:** Auth required — OAuth type unknown (org_internal TBD)

#### Stack
- Frontend: Vue.js SPA, Vite
- Auth: Google OAuth via `gapi` → POST `{token: <Google idToken>}` to backend
- Backend: `data-entrypoint-api.limeinternal.com`
- BI: Tableau dashboards embedded

#### Google OAuth Client ID (data portal)
`523585829004-htvk44bls5vjaq562ir5ncf0h1lp6i69.apps.googleusercontent.com`
- **Redirect URI:** UNKNOWN — need to trigger `gapi.login()` in browser to discover
- **org_internal status: UNTESTED** — Chrome extension disconnected before sign-in completed

#### Backend API: data-entrypoint-api.limeinternal.com
All return 401 (Unauthorized) with correct `Origin: https://data.limeinternal.com` header.
CORS: Requires `Origin: https://data.limeinternal.com` header (otherwise 403 "CORS Forbidden")

**High-Value Endpoints Discovered (from JS bundle):**
| Endpoint | Method | Notes |
|---|---|---|
| `/auth/login` | POST | `{token: <Google idToken>}` |
| `/scheduled-queries?user=<email>` | GET | **IDOR candidate — email param** |
| `/external-scheduled-queries?user=<email>` | GET | **IDOR candidate — email param** |
| `/snowflake/queries?email=<email>` | DELETE | **IDOR candidate — email param** |
| `/snowflake/snowflake-data` | GET | Snowflake data (sensitive) |
| `/query-pad/shared-query-result?queryId=X&fileName=X` | GET | **IDOR — queryId param** |
| `/admin-console/admin-users` | GET | **Admin endpoint** |
| `/admin-console/scheduled-queries` | GET | **Admin endpoint** |
| `/admin-console/login-notices` | GET/DELETE | **Admin endpoint** |
| `/admin-console/restricted-modules` | GET | **Admin endpoint** |
| `/custom-dashboards/metric-summary-v2` | GET | Dashboard data |
| `/alerts/subscriptions` | DELETE | Subscriptions |
| `/forum/post/<id>` | PATCH | Forum posts |

---

### 3. NEW: orchard.limeinternal.com — "Lime Orchard" [MEDIUM PRIORITY]
**Status:** Not tested beyond fingerprint

#### Stack
- Old stack: React 16, Handlebars, jQuery, Bootstrap 4, Babel standalone
- Auth: **GitHub OAuth** — client_id `227cbe637faa5af49747`, scope: `user, user:email, read:org`
- Login at `/login`

#### Notes
- `read:org` scope = checks GitHub org membership (likely `LimeBike` org)
- Old React/jQuery stack — potential for XSS, logic flaws
- `/login?next=` pattern — possible open redirect (P4, but excluded by ROE)

---

### 4. gpt.lime.bike [LOW PRIORITY — UNREACHABLE]
- DNS resolves but connection refused from our host (exit 6 direct, 502 via Caido)
- Likely internal-only / not currently deployed externally

---

### 5. lp.lime.bike [NOT YET EXPLORED]
- Returns 200 with Vite SPA (React + MUI)
- JS bundle: `/assets/index-B8eyC4Wd.js`

---

## Next Steps (Priority Order)

1. **[P1 CANDIDATE] data.limeinternal.com — Auth test:**
   - Determine if `org_internal` restriction applies to client_id `523585829004-...`
   - If NOT restricted: any Google account → Lime Data Portal access → Snowflake queries, dashboards, admin console = P1
   - Method: Navigate data.limeinternal.com, click Login, use `hoc4life8@gmail.com`
   - Capture Google idToken from `/auth/login` POST in Caido
   - Test backend response

2. **[P2/P3 CANDIDATE] data-entrypoint-api IDOR (post-auth):**
   - Once authenticated, test `?user=` and `?email=` params with other users' emails
   - Test admin-console endpoints with non-admin session

3. **[MEDIUM] orchard.limeinternal.com:**
   - Check if GitHub OAuth restricts to `LimeBike` org members only
   - Explore endpoints once GitHub OAuth behavior known

4. **[LOW] lp.lime.bike:**
   - Pull JS bundle, enumerate endpoints

---

## Files
- `hunt_state.md` — this file
- `targets.md` — admintool endpoint map + secrets
- `scans.md` — all scan outputs
- `main-B8ww8qo8.js` — admintool JS bundle (1.5MB)
- `/tmp/data_lime_bundle.js` — data portal JS bundle (6.7MB) [NOT saved to disk yet]
- `httpx_admintool.txt` — admintool fingerprint
