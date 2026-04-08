# AD Attack Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. No Credentials (Network Access Only)
**Signal:** On the network but no domain creds yet

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Passive Network Capture (Responder Analyze) | AD_Enumeration.md | Root on Linux attack box | Host identification, NTLMv2 hashes |
| Ping Sweep (fping) | AD_Enumeration.md | Network access | Live host list |
| Kerbrute Username Enumeration | AD_Enumeration.md | Port 88 open, username wordlist | Valid usernames, AS-REP hashes |
| LLMNR/NBT-NS Poisoning (Inveigh) | AD_Enumeration.md | Windows foothold on subnet | NTLMv2 hashes |
| ASREPRoasting (no creds, Linux) | Kerberoasting.md | Port 88, username list | AS-REP hashes for cracking |
| Password Policy Enumeration | AD_Enumeration.md | SMB/RPC/LDAP access (null session) | Lockout policy for safe spraying |
| Password Spraying (Linux) | AD_Enumeration.md | Username list, lockout policy known | Valid domain creds |

→ **Next:** Crack hashes or spray → go to [2. Valid Domain User] or [3. NTLM Hash]

---

## 2. Valid Domain User (No Admin)
**Signal:** Have username:password for a domain account without admin rights

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| BloodHound Collection (Linux) | AD_Enumeration.md | bloodhound-python installed | Full AD attack path graph |
| PowerView Key Enumeration | AD_Enumeration.md | PowerView loaded on Windows | Users, groups, trusts, shares, GPOs |
| Kerberoasting (Linux/Impacket) | Kerberoasting.md | Port 88 access | TGS hashes for cracking |
| Kerberoasting (Windows/Rubeus) | Kerberoasting.md | Domain-joined host | TGS hashes with opsec control |
| ASREPRoasting (Windows/Rubeus) | Kerberoasting.md | Knowledge of no-preauth accounts | AS-REP hashes |
| Find Abusable ACLs (PowerView) | ACL_Abuse_Enum.md | PowerView loaded | Abusable ACEs on domain objects |
| Bulk ACL Check per User | ACL_Abuse_Enum.md | AD module available | Objects your user controls |
| LDAP Enumeration (groups, OUs, SPNs) | LDAP_Enum.md | RSAT or LDAP access | Group structure, admin accounts |
| DNS Zone Dump (adidnsdump) | AD_Enumeration.md | LDAP access | Hidden hosts in AD DNS |
| Snaffler Share Crawler | AD_Enumeration.md | Domain-joined Windows host | Passwords in file shares |
| PASSWD_NOTREQD / Description Hunting | AD_Enumeration.md | PowerView loaded | Weak accounts, embedded passwords |
| Delegation Enumeration | Net_Exec_Enum.md | LDAP access | Unconstrained/constrained delegation targets |
| Security Controls Enumeration | AD_Enumeration.md | Windows foothold | AV, AppLocker, LAPS, CLM status |
| Printer Bug Check (MS-RPRN) | AD_Enumeration.md | rpcdump.py | Coercion viability |
| Password Spraying (Windows) | AD_Enumeration.md | Domain-joined host, lockout policy | More valid creds |
| Exchange Version Enumeration | Exchange_Attacks.md | HTTPS access to Exchange | CVE matching |
| SCCM Discovery (SCCMHunter) | SCCM_Attacks.md | Network access to SCCM | SCCM infrastructure map |

→ **Next:** Kerberoast → crack → [4. Local Admin]. ACL abuse → [5. GenericWrite/WriteDACL]. Find delegation → [7/8]. Find MSSQL → [6]. Find relay targets → [9]. Find ADCS → [10]. Find SCCM → [13].

---

## 3. NTLM Hash (No Plaintext)
**Signal:** Have NT hash from credential dump, Responder, or Kerberoasting

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Pass-the-Hash (evil-winrm) | Lateral_Movement.md | WinRM open, user has admin | Interactive PowerShell shell |
| Pass-the-Hash (impacket psexec/wmiexec) | Lateral_Movement.md | SMB/WMI access, local admin | SYSTEM or semi-interactive shell |
| Over-Pass-the-Hash (Mimikatz) | Credential_Dumping_Local.md | Mimikatz on host | Kerberos TGT in new process |
| Over-Pass-the-Hash (Rubeus /opsec) | Credential_Dumping_Local.md | AES256 key, Rubeus | Stealthy Kerberos auth |
| Domain Auth with NTLM (nxc) | Net_Exec_Auth.md | SMB access | Authenticated SMB session |
| RDP Restricted Admin Mode | Lateral_Movement.md | Restricted Admin enabled | GUI RDP session via hash |
| NTLM Relay (ntlmrelayx) | NTLM_Relay.md | Signing disabled on targets | Relay to other services |

→ **Next:** Shell obtained → [4. Local Admin on Host]

---

## 4. Local Admin on Host (Not DC)
**Signal:** Admin/SYSTEM shell on a domain-joined workstation or member server

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Mimikatz Credential Dump | Credential_Dumping_Local.md | SeDebugPrivilege | NTLM hashes, Kerberos tickets |
| DPAPI Credential Manager Dump | Credential_Dumping_Local.md | Access to user profiles | Saved passwords (scheduled tasks, etc.) |
| procdump → Offline Mimikatz Parse | Credential_Dumping_Local.md | procdump.exe available | LSASS dump evading on-target AV |
| Registry Hive Dump → secretsdump | Credential_Dumping_Local.md | reg.exe access | SAM hashes, LSA secrets |
| Token Impersonation (Incognito) | Token_Manipulation.md | DA sessions on host | DA token for privilege escalation |
| SharpHound Collection | Bloodhound.md | SharpHound binary | AD graph from on-target |
| Sticky Notes Credential Loot | Lateral_Movement.md | Admin share access | Plaintext passwords |
| AMSI Bypass → Tool Loading | AMSI_Evasion_Bypass.md | PowerShell session | Load PowerView, Rubeus, etc. |
| AppLocker Bypass | AMSI_Evasion_Loader.md | AppLocker active | Execute unsigned tools |
| UAC Bypass (FODHelper/DiskCleanup) | AMSI_Evasion_Loader.md | Medium integrity, local admin | High integrity shell |
| nxc Remote Cred Extraction (SAM/LSA) | Credential_Dumping_Remote.md | nxc + admin creds | Remote SAM/LSA dump |
| nxc LSASS Dump Modules | Credential_Dumping_Remote.md | nxc + admin creds | Remote LSASS parse |

→ **Next:** Find DA hash → [11. Domain Admin]. Find more creds → lateral to more hosts → repeat [4]. Find ACL rights → [5].

---

## 5. GenericWrite / WriteDACL / GenericAll on Object
**Signal:** BloodHound or ACL enum shows write rights on a user, group, or computer

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Targeted Kerberoasting (set fake SPN) | ACL_Abuse_Exploit.md | GenericWrite on user | TGS hash for cracking |
| ForceChangePassword | ACL_Abuse_Exploit.md | ForceChangePassword right | Target user password reset |
| AddMember (group membership) | ACL_Abuse_Exploit.md | AddMember on privileged group | Group privilege inheritance |
| WriteDACL → Grant DCSync | ACL_Abuse_Exploit.md | WriteDACL on domain head | DS-Replication rights → [11] |
| Shadow Credentials (Whisker + Rubeus) | Shadow_Credentials.md | GenericWrite + ADCS with PKINIT | TGT + NT hash of target |
| RBCD Attack (GenericWrite on computer) | Delegation_Attacks.md | Write on computer, MAQ > 0 | Admin on target computer |
| Logon Script Abuse (scriptPath) | Logon_Script_Abuse.md | GenericWrite on user | Code exec at next user logon |
| WriteDacl → Self-Add to Group | ACL_Abuse_Exploit.md | WriteDacl on group | Group membership |
| dacledit.py (Linux) | ACL_Abuse_Exploit.md | dacledit.py, valid creds | DACL modification from Linux |
| owneredit.py (Linux) | ACL_Abuse_Exploit.md | WriteOwner right | Object ownership change |
| targetedKerberoast.py (Linux) | ACL_Abuse_Exploit.md | GenericWrite, SPN set | TGS hash from Linux |
| net rpc group manipulation (Linux) | ACL_Abuse_Exploit.md | AddMember right, Samba tools | Group membership from Linux |
| pyGPOAbuse (GPO write from Linux) | ACL_Abuse_Exploit.md | Write rights on GPO | Local admin via GPO |

→ **Next:** DCSync → [11]. Password cracked → [4] or [3]. Group membership → escalate.

---

## 6. MSSQL Access
**Signal:** MSSQL port 1433 open with valid credentials (SQL or domain auth)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Login Enumeration (roles/privs) | MSSQL_Attacks.md | SELECT on sys tables | sysadmin, impersonation targets |
| Impersonation Chain → xp_cmdshell | MSSQL_Attacks.md | IMPERSONATE permission | OS command execution |
| Linked Server Traversal | MSSQL_Attacks.md | Linked servers configured | Cross-server/cross-forest RCE |
| UNC Path Injection (xp_fileexist) | MSSQL_Attacks.md | EXEC on xp_fileexist | SQL service account NTLM hash |
| xp_dirtree NTLM Coercion | Credential_Dumping_Remote.md | MSSQL access, SMB listener | SQL service account hash for relay |
| OLE Automation RCE | MSSQL_Attacks.md | sysadmin role | OS command exec (xp_cmdshell alt) |
| nxc mssql_priv (auto escalation) | MSSQL_Attacks.md | nxc installed | Auto impersonation → sysadmin |
| MSSQL Relay to NTLM (ntlmrelayx) | MSSQL_Attacks.md | Captured NTLM, MSSQL target | SQL exec as relayed user |
| Trustworthy DB Enumeration | MSSQL_Attacks.md | SELECT on sys.databases | Privesc via assembly creation |
| MSSQL via Sliver execute-assembly | MSSQL_Attacks.md | Sliver session, PowerUpSQL | In-memory SQL audit |

→ **Next:** OS command exec → [4]. Hash captured → [3] or [9].

---

## 7. Unconstrained Delegation Host
**Signal:** Computer with TrustedForDelegation flag, and you have admin on it

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Passive TGT Harvest (Rubeus monitor) | Delegation_Attacks.md | Admin/SYSTEM on deleg host | TGTs of connecting users |
| Printer Bug → DC TGT Capture | Delegation_Attacks.md | MS-RPRN on DC, SpoolSample | DC machine account TGT |
| Printer Bug → DC TGT (Sliver) | Unconstrained_Delegation.md | Sliver session, SpoolSample | DC TGT via C2 |
| Cross-Forest Escalation via Printer Bug | Unconstrained_Delegation.md | Parent DC has Spooler | Parent forest DC TGT |

→ **Next:** DC TGT → DCSync → [11. Domain Admin]

---

## 8. Constrained Delegation Account
**Signal:** Account/computer with msDS-AllowedToDelegateTo attribute

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| S4U + Altservice (User Account) | Constrained_Delegation.md | User hash (AES/NTLM), Rubeus | TGS as Admin to delegated svc |
| S4U + Altservice (Machine Account) | Constrained_Delegation.md | Machine hash, Rubeus/Mimikatz | LDAP TGS → DCSync |
| Cross-Domain Constrained Delegation | Constrained_Delegation.md | AES256 key, foreign domain target | Cross-domain service ticket |
| SPN Jacking (orphaned SPN hijack) | SPN_Jacking.md | WriteSPN on target computer | Forged ticket via S4U |
| SPN Jacking via Impacket (Linux) | SPN_Jacking.md | WriteSPN, SOCKS proxy | S4U from Linux |

→ **Next:** Service ticket → access service → [4] or [11].

---

## 9. NTLM Relay Opportunity
**Signal:** SMB signing disabled on targets, or coercion methods available

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Enumerate Relay Targets (signing off) | NTLM_Relay.md | Network access | Relay target list |
| Enumerate WebDAV Servers | NTLM_Relay.md | Domain creds | HTTP relay targets |
| Hash Farming via NTLM Theft Files | NTLM_Relay.md | Writable shares | Passive NTLMv2 collection |
| Coerce: PrinterBug (MS-RPRN) | NTLM_Relay.md | Spooler running on target | Forced NTLM auth |
| Coerce: PetitPotam (MS-EFSR) | NTLM_Relay.md | EFS RPC exposed | Forced NTLM auth (unauth possible) |
| Coerce: DFSCoerce (MS-DFSNM) | NTLM_Relay.md | DFS service running | Forced NTLM auth |
| Coerce: Coercer (multi-protocol scan) | NTLM_Relay.md | Domain creds | Auto-discover all coercion methods |
| NTLMRelayx → SMB Shell | NTLM_Relay.md | Signing disabled target | Authenticated SMB shell |
| NTLMRelayx → LDAP Domain Enum | NTLM_Relay.md | DC LDAP accessible | Full domain dump |
| NTLMRelayx → LDAP Machine Account | NTLM_Relay.md | LDAP relay + MAQ > 0 | Machine account for RBCD |
| NTLMRelayx → ACL Escalation | NTLM_Relay.md | High-priv auth relayed | DCSync rights granted |
| RBCD via NTLM Relay | NTLM_Relay.md | Machine auth + LDAPS | Admin on target via S4U |
| Shadow Credentials via Relay | NTLM_Relay.md | LDAP relay, PKINIT support | Cert-based auth to target |
| PetitPotam + ESC8 Relay to ADCS | DCSync_DomainTakeover.md | ADCS HTTP enrollment | DC cert → DC hash → DCSync |

→ **Next:** Shell → [4]. DCSync rights → [11]. Machine account → [5] RBCD. Certificate → [10].

---

## 10. ADCS Present
**Signal:** AD Certificate Services found in domain

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| ESC1 — Enrollee Supplies Subject | ADCS.md | Enrollment rights, SAN flag | Cert as DA → TGT |
| ESC3 — Certificate Request Agent | ADCS.md | Agent template + on-behalf-of | Cert as any user |
| ESC8 — NTLM Relay to HTTP Enrollment | ADCS.md | HTTP enrollment, no EPA | Machine cert → TGT + hash |
| ESC11 — NTLM Relay to RPC | ADCS.md | RPC NTLM auth enabled | Machine cert → TGT |
| Cross-Trust Certificate Abuse (ESC1) | Trust_Attacks.md | Parent CA template with SAN | Parent domain admin cert |

→ **Next:** Certificate → TGT → DA → [11]

---

## 11. Domain Admin Achieved
**Signal:** DA credentials or hash obtained; can DCSync

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| DCSync (Impacket/Linux) | DCSync_DomainTakeover.md | DS-Replication rights | All domain hashes |
| DCSync (Mimikatz/Windows) | DCSync_DomainTakeover.md | Mimikatz + replication rights | Targeted user hashes |
| NTDS.dit via Volume Shadow Copy | Credential_Dumping_Local.md | Admin on DC | Full domain hash database |
| Skeleton Key (Mimikatz) | Domain_Persistence.md | DA on DC | Universal backdoor password |
| DSRM Admin Backdoor | Domain_Persistence.md | DA on DC | Persistent local admin on DC |
| ACL Backdoor (DCSync grant) | Domain_Persistence.md | DA, PowerView | Hidden DCSync persistence |
| WMI/PSRemoting Backdoor | Domain_Persistence.md | DA | Low-priv user gets DC exec |
| DCShadow (stealth replication) | Domain_Persistence.md | DA/EA, Mimikatz | Silent AD attribute changes |
| Silver Ticket (service-level) | Domain_Persistence.md | Machine/service hash | Targeted service without DC |
| Golden Ticket | Trust_Attacks.md | krbtgt hash | Any user impersonation |
| Remote Reg Backdoor (DAMP) | Domain_Persistence.md | DA, DAMP toolkit | Persistent remote hash dump |

→ **Next:** If child domain → [12. Parent Escalation]. Otherwise → persistence complete.

---

## 12. Child Domain DA → Parent Escalation
**Signal:** DA in child domain, need Enterprise Admin in parent

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Golden Ticket + ExtraSID (Mimikatz) | Trust_Attacks.md | krbtgt hash, parent EA SID | Enterprise Admin |
| Golden Ticket + ExtraSID (Rubeus) | Trust_Attacks.md | krbtgt hash, Rubeus | Enterprise Admin |
| Golden Ticket + ExtraSID (Impacket) | Trust_Attacks.md | krbtgt hash, Impacket | Enterprise Admin from Linux |
| raiseChild.py (automated) | Trust_Attacks.md | Child DA creds, Impacket | Auto parent domain access |
| Inter-Realm TGT via Trust Key | Trust_Attacks.md | Trust account hash (DCSync) | Stealthier cross-domain TGT |
| Cross-Forest Kerberoasting | Trust_Attacks.md | Bidirectional trust | TGS hashes in trusted forest |
| Configuration NC ACL Abuse | Trust_Attacks.md | Write on CN=Configuration | Cert template/GPO modification |
| GPO Site-Linking (cross-domain) | Trust_Attacks.md | SYSTEM on child DC | GPO exec on parent DCs |
| GoldenGMSA | Trust_Attacks.md | KDS root key access | gMSA hash for PtH |
| Wildcard DNS Poisoning | Trust_Attacks.md | ADIDNS write in parent zone | NTLMv2 capture in parent |
| Cross-Domain Whisker + S4U | Trust_Attacks.md | Write on parent computer | Shadow cred → admin |
| Cross-Trust Cert Abuse (ESC1) | Trust_Attacks.md | Parent CA template enrollment | Parent DA cert |
| Cross-Forest SQL Linked Server | Trust_Attacks.md | MSSQL with cross-forest link | Cross-forest RCE |
| Foreign ACL Exploitation | Trust_Attacks.md | ACL rights on foreign objects | Cross-domain privesc |

→ **Next:** Enterprise Admin achieved → persistence via [11].

---

## 13. SCCM Infrastructure Found
**Signal:** SCCM/MECM infrastructure discovered during enumeration

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| PXE Boot Image Cred Extraction | SCCM_Attacks.md | TFTP access to PXE server | Domain join credentials |
| SCCMHunter Enumeration | SCCM_Attacks.md | Domain creds, network access | Site codes, managed devices |
| SCCMHunter Admin Console | SCCM_Attacks.md | SCCM Full Admin role | App deployment, script exec |
| DPAPI Secret Extraction (WMI) | SCCM_Attacks.md | Admin on SCCM server | NAA creds, task sequence secrets |
| Client Push Coercion (SharpSCCM) | SCCM_Attacks.md | Controlled host on network | SCCM push account hash |
| App Deployment RCE (SharpSCCM) | SCCM_Attacks.md | SCCM Full Admin | RCE on managed hosts |
| SCCM PetitPotam + Relay | SCCM_Attacks.md | SOCKS proxy, PetitPotam | SCCM machine account relay |

→ **Next:** Creds obtained → [2] or [3]. RCE → [4].
