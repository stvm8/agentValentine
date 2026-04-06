---
title: ctfTemplate
tags: #ctfPlayer
created: 2026-04-05
modified: 2026-04-05
type: note
---

# CTF Walkthrough: Machine Name

**Platform:** HTB / TryHackMe / etc. | **OS:** Linux/Windows | **Difficulty:** Easy/Medium/Hard | **IP:** 10.10.x.x

## Executive Summary
Provide a 2-3 sentence high-level summary of the attack path. Example: "The box starts with anonymous SMB access leaking credentials to a web portal. The web portal is vulnerable to CVE-XXXX leading to a shell as user. Privesc involves abusing a cronjob running as root to hijack a python script."

---

## Reconnaissance

### Nmap
Briefly describe the scan strategy and list the open ports.
```bash
# Insert raw Nmap output here
```
Write a brief analysis of the open ports. E.g., "Only SSH and HTTP are open. I'll start with HTTP enumeration."

### Web / SMB / Active Directory Enumeration
Break down the enumeration of the primary attack surface. Show directory fuzzing outputs (ffuf/gobuster), virtual host routing, or SMB share listings. Show the exact commands used.
```bash
# Insert relevant enumeration commands and output
```

---

## Shell as Username

### Vulnerability Discovery
Explain how the vulnerability was discovered. What was the exact parameter, misconfiguration, or CVE? Show the HTTP request or the source code snippet that proved it was vulnerable.

### Exploitation
Walk through the exact exploit path. If a custom script was written, provide the script or the exact command line syntax used to gain the reverse shell.
```bash
# Insert exploit command here
```

Show the proof of the initial shell and user.txt capture.
```bash
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat user.txt
REDACTED
```

---

## Shell as root

### Local Enumeration
Explain the PrivEsc vector. Did we upload LinPEAS? Find a SUID binary? Check `sudo -l`? Show the exact command and the output that revealed the misconfiguration.

### Privilege Escalation
Walk through the exploitation of the PrivEsc vector. Explain *why* it works (e.g., "Because the script imports a module from a directory we control, we can use Python Library Hijacking").
```bash
# Insert PrivEsc command here
```

Show the proof of the root shell and root.txt capture.
```bash
# id
uid=0(root) gid=0(root) groups=0(root)
# cat root.txt
REDACTED
```

---

## Beyond Root (Optional)
If applicable, analyze the underlying root cause of the vulnerability. Show the actual backend source code (e.g., PHP, C#, Bash script) retrieved from `loot.md` that caused the flaw, explaining how the developer made the mistake.
