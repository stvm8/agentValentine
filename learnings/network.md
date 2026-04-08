# Network & AD Security Learnings
# Domain: Active Directory, SMB, Kerberos, LDAP, Pivoting, Enterprise Infra
# Format: #Tag1 #Tag2 [YYYY-MM-DD] Issue: X -> Solution: Y
# Agents: netPen

#LDAP #tcpdump #Cleartext [2026-04-05] Issue: LDAP Simple Bind sends passwords in cleartext over TCP on port 389. Solution: Use tcpdump with cap_net_raw+ep capability to sniff binds on localhost/network interface.
#Linux #Capabilities #Privesc [2026-04-05] Issue: Binaries with =ep (all caps enabled) in user directories allow arbitrary file read/write as root. Solution: Check getcap -r on user home dirs and accessible binaries for escalation paths.
#Fail2ban #IptablesIP [2026-04-05] Issue: Aggressive nmap scans (--min-rate 5000) trigger automated IP bans for ~60-90 seconds. Solution: Use slower scans (-T2/-T3) or single ports. Wait for ban to lift before retrying.
#Jenkins #Groovy [2026-04-05] Groovy Script Console has direct JVM access to internal APIs: CredentialsProvider.lookupCredentials() extracts all credential types, hudson.util.Secret.decrypt() decrypts Jenkins-encrypted values, Java File I/O via new File() may bypass bash-level permission restrictions.
#Jenkins #Credentials [2026-04-05] Always enumerate plugin-specific config files (s3explorer.xml, etc.) for encrypted credential storage—multiple credential sets often exist with different permissions/purposes.
#Privesc #Password [2026-04-05] Password reuse across services/OS accounts is a high-yield enumeration vector—check backup scripts, deployment configs, CI/CD logs for plaintext passwords that may apply to root/admin accounts.
#Groovy #RCE [2026-04-05] Process output capture: avoid .text immediately after execute()—use consumeProcessOutput(StringBuffer, StringBuffer) + waitFor() pattern instead.
#Groovy #Privesc [2026-04-05] JVM File I/O (new File().text) may succeed where forked shell commands fail—JVM may inherit elevated permissions or capabilities that subprocess forking doesn't preserve.
#SSH #Auth [2026-04-05] Writing SSH keys via Groovy Java File API is viable privesc path when JVM has file write permissions that forked shells don't—critical for jenkins-to-root lateral movement.
