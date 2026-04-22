---
description: Generate a clean technical walkthrough with MITRE ATT&CK / OWASP mapping. Switch to Haiku before running. (e.g., /report client: Acme, platform: WebPortal)
disable-model-invocation: true
---
I am executing the `/report` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `client:`, `platform:`.

**TOKEN OPTIMIZATION:** Switch to Haiku model BEFORE running this skill to save output tokens.

## 1. Navigate & Read State
1. `cd <platform>/<client>`
2. Read ALL state files:
   - `scope.md` — engagement parameters and type
   - `vulnerabilities.md` — confirmed findings
   - `creds.md` — collected credentials
   - `progress.md` — full engagement timeline
   - `strikes.md` — failed vectors
   - `handoff.md` — original appraisal findings
   - Domain-specific: `endpoints.md`, `api_schema.md`, `ad_enum.md`, `network_topology.md`, `assets.md`, `iam_enum.md`, `loot.md`, `scans.md`

## 2. Detect Report Type
Read `scope.md` to determine `Type:`:
- **ctf:** Technical walkthrough. No business impact or remediation.
- **Real engagement (webapp/api/network/cloud):** Full report with business impact and remediation.

## 3. Generate Report
Load the appropriate template from this skill's `references/` directory:
- **CTF:** Read `references/ctf_template.md`
- **Real engagement (webapp/api/network/cloud):** Read `references/pentest_template.md`

Create `report.md` in the engagement directory by filling in every placeholder in the template with data from the state files. Do not alter the template's structure or section order. Replace all `[placeholder]` fields; remove any sections that have no data (e.g., no lateral movement phase for a straight privesc).

Additional field mappings not in the template:
- **Classification block (pentest only):** Under each finding add:
  - OWASP: `<Web A01-A10 or API API1-API10>` (webapp/api only)
  - MITRE ATT&CK: `<Tactic> / <Technique ID> - <Technique Name>`
  - CWE: `<CWE-ID> - <CWE Name>`
- **Findings sort order (pentest only):** Critical → High → Medium → Low → Informational
- **CTF flags:** Populate from `loot.md` if present; otherwise leave the intentional placeholder.

## 4. Lesson Extraction
After generating the report, extract lessons for the Global Brain:
1. Review findings for novel techniques, bypasses, or mistakes.
2. **Dedup check:** `grep -i "<key_term>" {LEARNINGS}/<domain>.md`
3. Append new lessons using enriched tag format:
   `echo "#Tag1 #Tag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: X -> Solution: Y" >> {LEARNINGS}/<domain>.md`

## 5. Output
`[REPORT GENERATED] See <platform>/<client>/report.md. Lessons extracted: <count> entries to {LEARNINGS}/<domain>.md.`
