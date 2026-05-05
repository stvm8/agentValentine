# Proposal Loop

## Pre-Proposal Checklist (run as ONE bash call before writing any proposal)
```bash
cat <engagement>/strikes.md && \
grep -i "<vector_keyword>" {LEARNINGS}/<domain>.md && \
grep -i "<technology>" {LEARNINGS}/<domain>.md && \
grep -i "<technology>" {PLAYBOOKS}/<dir>/INDEX.md
```

## Proposal Format
```
[THREAT MODEL] <triad> -> <deduction>
[STRIKE CHECK] Vector: <name> | Strikes: <N>/3
[OPSEC] Rating: <Low|Med|High> | Note: <why — from matched playbook entry>
[PROPOSAL] Task: <bounded action>
Failure Risk: <what could make this fail; if high, consider alternatives first>
Expected Outcome: <what this achieves>
[HALTING. AWAITING USER APPROVAL.]
```

## Rules
1. Write proposal as a raw Markdown code block — never execute tools in the same turn.
2. Stop generating immediately after the proposal. Yield to user.
3. Only execute after user replies "yes".
4. If Strike Check shows 3/3 — do NOT propose the vector. Output [STUCK] instead.

## Reactive Playbook Lookup
On every new signal (port, tech, response header, error message):
1. `grep -i "<signal>" {PLAYBOOKS}/<category>/INDEX.md`
2. Check **Prereq** column — do you have what's needed?
3. If prereqs met, read the matched technique file only.
4. Cite the playbook source in the Threat Model.

## Form Recon Rule
Before submitting ANY web form, fetch the form HTML and extract all `<input>` field names.
Never assume field names. This prevents wrong-field errors that waste CAPTCHA attempts and cause 500s.
```bash
curl -s <url> | grep -o '<input[^>]*>' | grep -o 'name="[^"]*"'
```

## Technology Constraint Check
Before exploiting a library or framework-specific vulnerability, grep learnings for that library name.
Known constraints (e.g., librsvg blocks XXE, ssrf_filter blocks RFC1918) are discovered this way.
```bash
grep -i "<library_name>" {LEARNINGS}/<domain>.md
```
