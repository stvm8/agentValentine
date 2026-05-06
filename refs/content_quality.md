# Content Quality Standard — Portable, Novel Techniques Only

## The Rule
Learnings and Playbook entries must be written so they apply to any future engagement against any target.
Strip all target-specific context (hostnames, IPs, client names, app names, flags, credentials) before saving.
This rule applies regardless of which model is running — it is enforced at write time, not review time.

## Test Before Saving
Ask: "Could this entry help me on a completely different engagement next month, against a different target?"
- YES → save it
- NO → it is an ops note; belongs in `progress.md`, `loot.md`, or `vulnerabilities.md`, NOT in learnings or Playbooks

## Anti-Patterns (never save these forms)

❌ Target-named learning:
`#OpenVaultBank #BOLA — /accounts/{id} has no auth check on OpenVaultBank`

❌ Hardcoded IP or path:
`Step 3: curl http://10.10.14.22/shell.php`

❌ Flag or loot artifact:
`The flag was in /home/ctf/flag.txt on machine X`

❌ Client-specific tool invocation:
`nuclei -u https://target-client.com -t cves/`

## Correct Patterns

✅ Generic technique with universal trigger:
`#BOLA #IDOR — Integer IDs on user-owned resource endpoints often lack server-side ownership checks; always enumerate sequential IDs with a different user's JWT before assuming authorization is enforced`

✅ Constraint with universal scope:
`#SSRF #Filter — RFC1918 filter may block 127.0.0.1 literally but miss decimal (2130706433), octal (0177.0.0.1), and IPv6 (::1) representations; always try all forms before concluding SSRF is blocked`

✅ Bypass with transferable lesson:
`#WebShell #WAFBypass #WordPress — Plugin name string triggers signature check at install; use convincing plugin metadata (Plugin Name, Plugin URI pointing to wordpress.org) to bypass name-based detection`

✅ Technique with trigger + prereq + yield (Playbook entry):
```
### Technique Name [added: YYYY-MM]
- **Tags:** #Primary1 #Primary2 #Alias1 #Alias2
- **Trigger:** <observable condition that should lead here — no target names>
- **Prereq:** <what you must have — generic>
- **Yields:** <what you get — generic>
- **Opsec:** Low | Med | High
- **Context:** <when/why — transferable reasoning>
- **Payload/Method:** <commands with TARGET/ATTACKER placeholders, not real IPs>
```

## Placeholders for Commands
Use these in Payload/Method sections — never real addresses:
- `TARGET` — victim host/IP
- `ATTACKER` — your listener IP
- `LHOST` / `LPORT` — reverse shell parameters
- `DOMAIN` — target domain
- `USER` / `PASS` — credential placeholders

## Model-Switch Durability
This standard lives in `refs/content_quality.md` and is referenced from `learning_format.md` and `reporting.md`.
Any model loaded mid-engagement must read this file before writing any learning or playbook entry.
The CLAUDE.md Pre-Proposal Checklist step 2 (`lq.py` dedup) enforces dedup; this file enforces quality.
