# Windows Privilege Escalation Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Low-Privilege Shell Obtained
**Signal:** User-level shell on a Windows host, need to escalate to SYSTEM or admin

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| whoami /priv → Potato Attacks | Potato_Attacks.md | SeImpersonatePrivilege or SeAssignPrimaryToken | SYSTEM shell |
| Unquoted Service Path Exploitation | Service_Abuse.md | Unquoted path with spaces + write access | SYSTEM shell via service restart |
| Weak Service Permissions | Service_Abuse.md | Writable service binary or config | SYSTEM shell via service restart |
| AlwaysInstallElevated | Service_Abuse.md | Registry key enabled | SYSTEM via malicious MSI |
| DLL Hijacking via Missing DLL | Service_Abuse.md | Missing DLL in writable application dir | Code execution as service user |
| RunasCs with Known Creds | Token_Impersonation.md | Plaintext creds for another user | Shell as target user |

→ **Next:** SYSTEM → done. Higher-priv user → [2]. SeImpersonate found → [3].

---

## 2. Credential Access
**Signal:** Need to extract credentials for lateral movement or privilege escalation

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| LaZagne for Plaintext Credentials | Credential_Access.md | Shell on Windows host | Browser, email, WiFi, vault creds |
| Windows Credential File Decryption | Credential_Access.md | .cred file + same user context | Plaintext username and password |
| osTicket DB Backup Crack | Credential_Access.md | DB backup found | osTicket admin credentials |
| Credential Vault Dump (Mimikatz) | Credential_Access.md | SYSTEM/admin + Sliver session | Vault plaintext credentials |
| Windows Event Log Credential Leakage | Privilege_Escalation.md | Event Log Reader access | Creds from command-line logging |
| NFS Share Looting | Credential_Access.md | NFS port 2049 open | Config files with passwords |
| rsync File Exfil + SSH Key Theft | Credential_Access.md | rsync port 873 open | SSH keys, home directories |

→ **Next:** Admin creds → [4]. DA creds → AD/_FLOW.md. Service creds → lateral movement.

---

## 3. SeImpersonatePrivilege Available
**Signal:** `whoami /priv` shows SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege (common on IIS/MSSQL service accounts)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| PrintSpoofer | Potato_Attacks.md | Win10/Server 2019+ | SYSTEM shell |
| GodPotato | Potato_Attacks.md | .NET 4.x on target, any modern Windows | SYSTEM shell |
| JuicyPotato | Potato_Attacks.md | Server 2016/2019, valid CLSID | SYSTEM shell |
| SweetPotato | Potato_Attacks.md | Multiple OS versions | SYSTEM shell |
| RoguePotato | Potato_Attacks.md | When JuicyPotato fails + attacker OXID | SYSTEM shell |

→ **Next:** SYSTEM → extract creds → [2] or done.

---

## 4. Local Admin / SYSTEM Obtained
**Signal:** Have SYSTEM or local admin access, need to move laterally or extract domain creds

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Credential Vault Dump (Mimikatz) | Credential_Access.md | SYSTEM + Sliver/meterpreter | Plaintext/NTLM creds from vault |
| Incognito Token Impersonation | Token_Impersonation.md | DA token cached on host | DA session |
| Named Pipe Impersonation | Token_Impersonation.md | Service connects to named pipe | Service account token |
| SeBackupPrivilege → Registry Dump | Privilege_Escalation.md | Backup Operators group | SAM/SYSTEM hives → NTLM hashes |

→ **Next:** Domain creds → AD/_FLOW.md. Need more hosts → lateral movement.

---

## 5. Service Account (IIS/MSSQL/Service)
**Signal:** Running as a Windows service account (IIS AppPool, MSSQL, etc.)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Potato Attacks (any variant) | Potato_Attacks.md | SeImpersonatePrivilege | SYSTEM shell |
| Named Pipe Impersonation | Token_Impersonation.md | Can create named pipe | Higher-priv token |

→ **Next:** SYSTEM → [4].
