# Web & API Security Learnings
# Domain: Bug Bounty, Web App Testing, API Security
# Format: #Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y
# Agents: bountyHunter, webApiPen

#JustEat #OIDC #JWT [2026-04-05] Issue: JWT from browser localStorage works in curl WITHOUT proxy. Caido proxy strips/corrupts Authorization header. Solution: Always test curl without -x for JWT-authed endpoints.
#JustEat #OIDC #JWT [2026-04-05] Issue: Manual hex transcription of JWT corrupts bytes. Solution: Split JWT at dots (console.log each part separately) - each part alone doesn't trigger extension's JWT block filter.
#JustEat #JWT #Auth [2026-04-05] Issue: je-at cookie (sameSite:lax, domain:just-eat.co.uk) NOT sent cross-domain to uk.api.just-eat.io. Solution: API uses Bearer token in Authorization header, set explicitly by SPA JS from oidc.user localStorage key.
#JustEat #IDOR #Consumer [2026-04-05] Issue: /consumer/{id}/orders/uk returns 404 - no direct consumer ID path. Only /consumer/me/orders/uk (200) exists. consumerId resolved from JWT sub claim, not from URL or injected headers.
#JustEat #IDOR #Headers [2026-04-05] Issue: X-Consumer-ID, X-User-ID, X-Forwarded-User, X-JWT-Sub headers all ignored - consumerId stays bound to JWT sub. Header injection IDOR: negative on this endpoint.
#Lime #OAuth #Google [2026-04-05] Issue: admintool client_id org_internal — Google-level restriction blocks non @li.me/@lime.bike accounts. Frontend vde domain check is redundant. -> Both frontend AND GCP app settings enforce domain.
#Lime #API #CORS [2026-04-05] Issue: data-entrypoint-api.limeinternal.com returns 403 CORS Forbidden without Origin header -> Fix: Always add Origin + Referer matching the SPA domain.
#OpenVaultBank #API #InfoDisc [2026-04-05] Issue: /health endpoint leaks full DB credentials + JWT signing hints unauthenticated -> Always probe /health, /status, /ping, /debug on any FastAPI/Rails app; check for DB URLs, secrets, flags.
#OpenVaultBank #MassAssign #PrivEsc [2026-04-05] Issue: PUT /profile accepts role field, escalates customer to admin -> Check all PUT/PATCH profile/user endpoints for mass assignment; send {"role":"admin"} as first test.
#OpenVaultBank #BOLA #Accounts [2026-04-05] Issue: GET/PUT /accounts/{id} has no ownership check, any valid JWT reads/writes any account -> Integer IDs + no owner validation = BOLA; always enumerate sequential IDs with your token.
#OpenVaultBank #ResetCode #ATO [2026-04-05] Issue: POST /auth/reset-request returns debug_code in response body (3-digit) -> Instant ATO for any user. Always check reset endpoints for leaked codes in response body, headers, or debug fields.
#OpenVaultBank #API #Debug [2026-04-05] Issue: Debug endpoint /api/v1/debug exposed unauthenticated with flag + JWT hints + registered users. Solution: Always fuzz for /debug, /test, /dev on any API; check api_logs for 200 status non-standard paths.
#OpenVaultBank #SSRF #DB [2026-04-05] Issue: Leaked Supabase DB creds from /health -> psql direct access -> pgjwt functions available for JWT operations, pg_net for SSRF out. Solution: DB creds in health = full DB access; always try psql and enumerate extensions (pgjwt, pg_net, http).
#OpenVaultBank #Register #API [2026-04-05] Issue: POST /auth/register required undocumented 'ssn_last4' field — 422 without it. Solution: On 422 'field required' check Pydantic error 'loc' array for missing field names.
#PromptInjection #SSRF #LLM #IndirectInjection #FileSSRF #WebSearch #Ollama #ToolAbuse #FileRead #CredentialDisclosure [2026-04-23] Technique: web_search tool in Ollama/uvicorn apps often uses requests/urllib without scheme validation. Pass file:///path/to/file as the search URL — model fetches raw file contents from disk, bypassing PHP execution. Works even on small models (0.6b) because web_search is a simpler action than read_file. Chain: direct user ask → model calls web_search(url=file://...) → server reads file → model returns contents verbatim.
