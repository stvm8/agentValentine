# NetExec (nxc) — Authentication & Spraying

## Authentication & Password Spraying

### Anonymous Logon Test [added: 2026-04]
- **Tags:** #nxc #NetExec #AnonymousLogon #NullSession #SMBEnum #InitialAccess #T1078
- **Trigger:** New target discovered; checking for unauthenticated SMB access
- **Prereq:** Network access to target on SMB port 445
- **Yields:** Confirmation of anonymous/null session access for unauthenticated enumeration
- **Opsec:** Low
- **Context:** Check if target allows anonymous/null SMB sessions.
- **Payload/Method:** `nxc smb <target> -u 'nop' -p ''`

### Domain Auth with NTLM Hash (Pass-the-Hash) [added: 2026-04]
- **Tags:** #nxc #PassTheHash #NTLM #PTH #SMBAuth #CredentialReuse #T1550.002
- **Trigger:** NTLM hash obtained from credential dump; need to authenticate without plaintext
- **Prereq:** Valid NTLM hash; target with SMB port 445 open
- **Yields:** Authenticated SMB session using NTLM hash (no plaintext password needed)
- **Opsec:** Med
- **Context:** Have NTLM hash, spray or authenticate across targets.
- **Payload/Method:** `nxc smb <target> -u <user> -H <NTLM_HASH>`

### AES Key Kerberos Auth [added: 2026-04]
- **Tags:** #nxc #AESKey #KerberosAuth #StealthAuth #EncryptionKey #T1550.003
- **Trigger:** AES key obtained from credential dump; want stealthier Kerberos authentication
- **Prereq:** AES-128 or AES-256 key from credential dump
- **Yields:** Authenticated session via Kerberos (stealthier than NTLM, avoids NTLM logging)
- **Opsec:** Low
- **Context:** Have AES-128 or AES-256 key from credential dump. Authenticate via Kerberos (stealthier than NTLM).
- **Payload/Method:** `nxc smb <target> -u <user> --aesKey <AES_128_or_AES_256>`

### Kerberos ccache Auth [added: 2026-04]
- **Tags:** #nxc #ccache #KRB5CCNAME #KerberosTicket #TicketAuth #T1550.003
- **Trigger:** Have a valid Kerberos ccache file from ticket forging or extraction
- **Prereq:** Valid ccache file set in KRB5CCNAME environment variable
- **Yields:** Authenticated session using existing Kerberos ticket (no credentials needed)
- **Opsec:** Low
- **Context:** Have a valid ccache file (e.g., from KRB5CCNAME). Authenticate without plaintext creds.
- **Payload/Method:** `nxc smb <target> --use-kcache`

### Password Spray with Lockout Safety [added: 2026-04]
- **Tags:** #nxc #PasswordSpray #NoBruteforce #LockoutSafe #CredentialAttack #T1110.003
- **Trigger:** Valid username list obtained; password policy checked (lockout threshold known)
- **Prereq:** Username list; password list; knowledge of lockout threshold
- **Yields:** Valid domain credentials with lockout-safe spraying (one password per user)
- **Opsec:** Med
- **Context:** Have user list and password list. Test one password per user (line-by-line) to avoid lockout.
- **Payload/Method:** `nxc smb <target> -u users.txt -p passwords.txt --no-bruteforce`

### Continue-on-Success Spray [added: 2026-04]
- **Tags:** #nxc #PasswordSpray #ContinueOnSuccess #AllValidCreds #BulkSpray #T1110.003
- **Trigger:** Spraying and want to find ALL valid credentials, not just the first match
- **Prereq:** Username list; target password; network access to target
- **Yields:** Complete list of all valid credentials for the sprayed password
- **Opsec:** Med
- **Context:** Default nxc stops after first valid cred. Use this to find ALL valid creds.
- **Payload/Method:** `nxc smb <target> -u users.txt -p 'Password1' --continue-on-success`

---

## SMB Enumeration

### Generate SMB Relay Target List [added: 2026-04]
- **Tags:** #nxc #SMBSigning #RelayTargets #NTLMRelay #SigningDisabled #T1557.001
- **Trigger:** Planning NTLM relay attack; need to identify hosts without SMB signing
- **Prereq:** Network access to target subnet on SMB port 445
- **Yields:** Text file of hosts with SMB signing disabled (viable relay targets)
- **Opsec:** Low
- **Context:** Identify hosts without SMB signing for NTLM relay attacks.
- **Payload/Method:** `nxc smb <target/CIDR> --gen-relay-list relay_targets.txt`

### Enumerate Active Sessions [added: 2026-04]
- **Tags:** #nxc #SessionEnum #UserHunting #TokenImpersonation #LoggedOnUsers #T1033
- **Trigger:** Looking for where high-value users (DA, EA) have active sessions
- **Prereq:** Valid domain credentials; SMB access to target
- **Yields:** List of active user sessions on target (for token impersonation targeting)
- **Opsec:** Low
- **Context:** Find where high-value users are logged in (target for token impersonation).
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> --sessions`

### Enumerate Logged-On Users [added: 2026-04]
- **Tags:** #nxc #LoggedOnUsers #UserEnum #SessionDiscovery #ActiveSessions #T1033
- **Trigger:** Need to identify which users have active sessions on a specific host
- **Prereq:** Valid domain credentials; SMB access to target
- **Yields:** List of users with active sessions on the target host
- **Opsec:** Low
- **Context:** Identify which users have active sessions on a host.
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> --loggedon-users`

### RID Brute-Force User Enumeration [added: 2026-04]
- **Tags:** #nxc #RIDBrute #UserEnum #RIDCycling #AccountDiscovery #T1087.002
- **Trigger:** LDAP restricted or need to enumerate users via alternative method
- **Prereq:** Valid domain credentials (or null session if allowed); SMB access
- **Yields:** Complete user and group list via RID cycling (works even with restricted LDAP)
- **Opsec:** Med
- **Context:** Enumerate users via RID cycling (works even with restricted LDAP).
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> --rid-brute 10000`

### Password Policy Enumeration [added: 2026-04]
- **Tags:** #nxc #PasswordPolicy #LockoutThreshold #SprayPrep #PolicyEnum #T1201
- **Trigger:** Before password spraying; need to know lockout threshold and complexity
- **Prereq:** Valid domain credentials; SMB access to DC
- **Yields:** Password policy details (lockout threshold, complexity, min length) for safe spraying
- **Opsec:** Low
- **Context:** Check lockout threshold before spraying.
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> --pass-pol`

### WMI Query via SMB [added: 2026-04]
- **Tags:** #nxc #WMI #WMIQuery #ServiceEnum #RemoteQuery #T1047
- **Trigger:** Need to run arbitrary WMI queries on remote host via nxc
- **Prereq:** Valid domain credentials with WMI access; SMB access to target
- **Yields:** WMI query results (services, processes, system info) from remote host
- **Opsec:** Low
- **Context:** Run arbitrary WMI queries through nxc.
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> --wmi "SELECT * FROM Win32_Service WHERE State='Running'"`

### Local Account Auth via WinRM (Drop Domain Prefix) [added: 2026-04]
- **Tags:** #WinRM #LocalAccount #CredentialReuse #LateralMovement #EvilWinRM #LocalAdmin
- **Trigger:** Domain user creds obtained; host has a local account with the same username and password (common with service/admin accounts recycling passwords)
- **Prereq:** Plaintext password; local account on target with same credentials as domain account
- **Yields:** WinRM shell as local administrator (Administrators group membership, not just domain user)
- **Opsec:** Low
- **Context:** When authenticating to WinRM with a domain prefix (`domain\user`), you get domain user privileges. Dropping the domain prefix forces local account authentication. If the password is reused and the local account is in the local Administrators group, this grants admin access even when the domain account is not a local admin. Check `net user <username>` to confirm local group membership before attempting.
- **Payload/Method:**
  ```bash
  # Domain auth (limited privileges)
  evil-winrm -i <IP> -u 'domain\user' -p 'Password'

  # Local auth (may yield local admin if account exists locally with same password)
  evil-winrm -i <IP> -u user -p 'Password'    # no domain prefix

  # Verify local group membership first:
  # net user <username>   → look for "Local Group Memberships  *Administrators"
  ```
