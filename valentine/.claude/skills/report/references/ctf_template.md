# [Machine Name] — [Platform] CTF Writeup

> **Author:** [Your Handle]
> **Date:** [YYYY-MM-DD]
> **Published:** [Blog/Platform URL]

---

## Machine Info

| Field      | Value                          |
|------------|-------------------------------|
| Platform   | [HackTheBox / TryHackMe / etc] |
| OS         | [Windows / Linux / Other]      |
| IP         | [Target IP]                    |
| Difficulty | [Easy / Medium / Hard / Insane]|
| Domain     | [domain.local — if applicable] |
| Tags       | [#kerberos #ad #web — etc]     |
| Status     | [Retired / Active]             |

---

## Summary

> One paragraph. Describe the full attack chain from initial foothold to root/admin, without revealing specific commands. This is a spoiler-light overview a reader can use to gauge difficulty and relevance.
>
> Example flow: *Unauthenticated RCE in the web application led to a low-privilege shell. Internal enumeration revealed a misconfigured service running as a privileged account, which was leveraged to obtain SYSTEM/root access.*

---

## Initial Enumeration

### Port Scan

```bash
# Full TCP scan — adjust flags to engagement rules
nmap -sC -sV -p- --open -oA scans/nmap_full [TARGET_IP]
```

**Key open ports:**

| Port | Service | Version / Banner |
|------|---------|-----------------|
| XX   | ...     | ...             |

### [Service / Protocol] Enumeration

Describe what you found and why it matters. Link each observation to a hypothesis.

```bash
# Command used
tool --flag value TARGET
```

**Relevant output:**
```
[Paste only the meaningful lines, not the full dump]
```

> **Note:** Explain any non-obvious behaviour or why a specific flag matters here.

---

## [Phase 2 Title — e.g., "Foothold / Initial Access"]

### [Sub-technique Name]

Explain the vulnerability or misconfiguration observed. Reference CVEs or technique names (e.g., AS-REP Roasting, SSRF, SQLi) where applicable.

> **Technical Detail:** Use blockquotes for deeper dives — protocol internals, exploit mechanics, or important caveats a reader should understand before running the commands.

```bash
# Exploit / attack command
tool --option value TARGET
```

**Output (truncated):**
```
[Relevant lines only]
```

**Result:** What was gained — credentials, shell, token, file, etc.

---

## [Phase 3 Title — e.g., "Lateral Movement / Post-Exploitation"]

### [Sub-technique Name]

Narrative connecting previous phase to this one. Why did you pivot here?

```bash
command args
```

```
[Output]
```

> **Note:** Any gotcha, timing issue, or tool quirk worth flagging.

**Result:** What was gained.

---

## Privilege Escalation

### [Vector Name — e.g., "ESC1 / Sudo Misconfiguration / Token Abuse"]

Describe the vulnerability class. Explain the pre-requisites and why this target met them.

> **Technical Detail:** Mechanism explanation — what the OS/application does wrong and why that translates to privilege gain.

```bash
# Enumeration step
enum-tool --flag TARGET

# Exploitation step
exploit-tool --flag TARGET
```

```
[Output showing escalated access]
```

**Result:** SYSTEM / root / Domain Admin obtained.

---

## Flags

| Flag       | Location / Method            |
|------------|------------------------------|
| User Flag  | [Path or brief description]  |
| Root Flag  | [Path or brief description]  |

> Flags are intentionally omitted. Solve it yourself — that's the point.

---

## Attack Chain

```
[Recon / Enumeration]
        |
[Initial Foothold — CWE/CVE or technique]
        |
[Lateral Movement / Post-Exploitation — if applicable]
        |
[Privilege Escalation — technique name]
        |
[Root / Domain Admin]
```

---

## Key Takeaways

- **Lesson 1:** What this machine teaches that's transferable to real engagements.
- **Lesson 2:** Any tool trick or technique worth remembering.
- **Lesson 3:** Detection / blue team perspective (optional).

---

## References

- [Tool / CVE / Technique Name](URL)
- [Relevant blog post or paper](URL)

---

*[Your Handle] | [Blog URL] | [Date]*
