# CTF State: Lightweight

## Status: COMPLETE ✓

**Date Completed:** 2026-04-03  
**Total Time:** ~45 minutes

## Objectives Achieved

- [x] **user.txt** — `d2b2088f03bd33f092be52ed1275737a`
- [x] **root.txt** — `95d5efd63ace6c01677886b034404813`

## Attack Chain Summary

1. Nmap → 3 open ports (SSH, HTTP, LDAP)
2. Web enum → Auto-provisioned SSH (user=IP, pass=IP)
3. SSH as 10.10.14.2 → Capability enumeration
4. tcpdump sniffing → Captured ldapuser2: `8bc8251332abe1d7f105d3e53ad39ac2`
5. su to ldapuser2 → Found backup.7z (AES encrypted)
6. john + rockyou → Cracked: `delete`
7. 7z extract → Found ldapuser1 in PHP: `f3ca9d298a553da117442deeb6fa932d`
8. su to ldapuser1 → Discovered /home/ldapuser1/openssl with `=ep`
9. openssl enc -in /root/root.txt → Root flag

## Key Vulnerabilities

- **LDAP Cleartext Bind** — Sniffable on localhost via tcpdump
- **Hardcoded Credentials** — ldapuser1 in backup PHP source
- **Linux Capability Misconfiguration** — openssl with all caps in user home
- **Weak Archive Password** — "delete" in rockyou top 1000

## Files Generated

- `scans.md` — Nmap output
- `creds.md` — All captured credentials
- `loot.md` — Flags and findings
- `network_topology.md` — Network state
- `Walkthrough_Lightweight.md` — Full writeup
