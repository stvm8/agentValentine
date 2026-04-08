# Linux Privilege Escalation Decision Flow

> Match your **current state** to a starting point below. Follow the techniques listed, then advance to the next starting point based on what you gain.

## 1. Low-Privilege Shell Obtained
**Signal:** User-level shell on a Linux host, need to escalate

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| sudo -l Enumeration + GTFOBins | Sudo_Misconfig.md | sudo installed, user can run sudo -l | NOPASSWD binaries, env_keep vars |
| SUID Binary Enumeration + GTFOBins | SUID_Capabilities.md | Shell access | SUID binaries exploitable for root |
| Linux Capabilities Abuse | SUID_Capabilities.md | Shell access, getcap available | Binaries with dangerous capabilities |
| Credentials in /etc/default/ Files | Privilege_Escalation.md | Read access to /etc/default/ | Plaintext service passwords |
| Writable /etc/passwd | Service_Misconfig.md | Write access to /etc/passwd | Root-equivalent user creation |

→ **Next:** Root via SUID/sudo → done. Creds found → try su/ssh. Nothing obvious → [2. Deeper Enumeration].

---

## 2. Deeper Enumeration (No Quick Wins)
**Signal:** Basic checks didn't yield root; need to look for scheduled tasks, misconfigs, and services

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Writable Cron Script Exploitation | Cron_PATH_Abuse.md | Cron job runs writable script as root | Root shell via cron |
| PATH Variable Hijacking | Cron_PATH_Abuse.md | Cron uses relative command path | Root shell via PATH hijack |
| Tar Wildcard Injection | Cron_PATH_Abuse.md | Cron runs tar with wildcard in writable dir | Root shell via checkpoint trick |
| Custom SUID Binary Exploitation | SUID_Capabilities.md | Unknown SUID binary found | Root shell via library hijack or logic flaw |
| Writable Systemd Service / Timer | Service_Misconfig.md | Writable .service file | Root shell via service restart |
| NFS no_root_squash Exploitation | Service_Misconfig.md | NFS share with no_root_squash | Root shell via SUID binary on NFS |

→ **Next:** Root obtained → done. Pivot needed → Pivoting/_FLOW.md.

---

## 3. sudo Misconfiguration Found
**Signal:** sudo -l reveals exploitable entries (NOPASSWD, env_keep, or outdated sudo version)

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| sudo -l + GTFOBins | Sudo_Misconfig.md | NOPASSWD entry for exploitable binary | Root shell |
| Sudo env_keep LD_PRELOAD | Sudo_Misconfig.md | env_keep+=LD_PRELOAD in sudoers | Root shell via malicious .so |
| LD_PRELOAD Privilege Escalation | Cron_PATH_Abuse.md | LD_PRELOAD preserved in sudo | Root shell via preloaded library |
| Sudo Version Exploit (Baron Samedit) | Sudo_Misconfig.md | sudo < 1.9.5p2 | Root shell via heap overflow |
| Sudo Token Reuse | Sudo_Misconfig.md | Another user recently used sudo | Root commands without password |

→ **Next:** Root obtained → done.

---

## 4. Container / Docker Environment
**Signal:** Running inside a Docker container or have Docker socket access

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| Docker Escape → Host Root SSH Key | Privilege_Escalation.md | Root in container, can mount host fs | Host root via SSH key |
| Duplicati Backup Service LFI | Privilege_Escalation.md | Duplicati on localhost port | Arbitrary file read as service user |

→ **Next:** Host root obtained → done. Need creds → [1] on host.

---

## 5. Credential Files Found
**Signal:** Found encrypted credential stores, password databases, or encrypted containers

| Technique | File | Key Prereq | Yields |
|---|---|---|---|
| VeraCrypt Container Cracking | Privilege_Escalation.md | .vc file found + hashcat | Decrypted volume contents |
| PasswordSafe .psafe3 Cracking | Privilege_Escalation.md | .psafe3 file found + hashcat | All stored credentials |

→ **Next:** Creds obtained → try su/ssh/lateral movement.
