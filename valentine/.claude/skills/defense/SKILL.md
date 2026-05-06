---
description: Write a defense.md for a completed lab or engagement by reading a writeup/notes file and filling the defense template. Syntax: /defense <path-to-writeup-or-notes-file>
---
I am executing the `/defense` skill.
**Source file:** $ARGUMENTS

**Task:**

## 1. Read Inputs

1. Read the source file provided in `$ARGUMENTS` — this is the lab writeup, genNotes.md, or engagement notes.
2. Read the defense template:
   `/Volumes/tksmac/Pentester/tksClaudeAgent_dev/valentine/Pwnedlabs/nonClaude/Azure/defense_template.md`

## 2. Derive Output Path

- The output file is `defense.md` written **in the same directory as the source file**.
- Example: if source is `Pwnedlabs/nonClaude/Azure/Lab X/genNotes.md`, output is `Pwnedlabs/nonClaude/Azure/Lab X/defense.md`.

## 3. Analyze the Attack Chain

Read the source file and extract:
- Every distinct exploitation step in sequence (recon → initial access → exploitation → lateral movement → impact).
- For each step: what was misconfigured or exposed, what the attacker did, and what it enabled.
- The attack chain summary as a one-line flow: `[Step 1] → [Step 2] → ... → [Outcome]`.

## 4. Write defense.md

Fill the template structure exactly — do not alter section order or remove sections. Apply these rules per section:

### Attack Chain Summary
- Condense the full sequence into one linear flow block. Use the `[Step] →` format from the template. Aim for 6–8 nodes maximum; combine closely related steps if needed.

### Findings (one block per distinct misconfiguration)
- Each finding maps to **one root cause** — not one tool or one step.
- **What happened:** Two sentences max. Name the misconfiguration, what the attacker did, and what it unlocked.
- **Fix:**
  - Lead with the highest-impact control that closes the vector entirely.
  - Follow with supporting controls (policy enforcement, monitoring).
  - Include a CLI snippet or config line if one exists for the fix.
  - End with a Defender plan or alert recommendation tied specifically to this finding.
- Findings count: write as many blocks as there are distinct root-cause misconfigurations in the source. Do not pad; do not merge unrelated findings.

### Detection Opportunities
- One KQL block per distinct detectable signal in the attack chain.
- Signals to cover: authentication anomalies, tooling sweeps, exploitation artifacts, lateral movement, data access.
- Each query must be runnable: correct table name, realistic `where` filters, meaningful `project` fields.
- Include a one-line comment above the query stating the log source and what it detects.
- Do not write placeholder queries — if a signal cannot be expressed in valid KQL from a known Azure log table (`SigninLogs`, `AzureActivity`, `StorageBlobLogs`, `AppServiceHTTPLogs`, `AuditLogs`, `AzureDiagnostics`), skip it.

### Priority Order
- List 4–6 items ordered by impact-to-effort ratio: highest blast-radius closures first, monitoring/logging last.
- Each item: bold action name + one-line reason stating what risk it closes.

## 5. Output

Write the completed `defense.md` to the derived output path.
Output a single confirmation line: `[DEFENSE WRITTEN] <output path> | <N> findings | <N> KQL detections`
