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
Create `report.md` in the engagement directory.

### Report Structure for Real Engagements (webapp/api/network/cloud):

```markdown
# Penetration Test Report: <Client> - <Platform>
**Date:** <date>
**Type:** <type>
**Scope:** <scope summary>
**Objective:** <objective>

## Executive Summary
<2-3 sentences: what was tested, overall risk posture, critical findings count>

## Findings

### Finding <N>: <Vulnerability Name>
**Severity:** Critical | High | Medium | Low | Informational
**CVSS:** <score if applicable>

**Classification:**
- OWASP: <Web A01-A10 or API API1-API10> (for webapp/api engagements)
- MITRE ATT&CK: <Tactic> / <Technique ID> - <Technique Name>
- CWE: <CWE-ID> - <CWE Name>

**Discovery:**
<How this was found. What observation triggered the investigation. Be specific — name the tool, endpoint, or signal.>

**Reasoning:**
<Why this action was taken. What the tester expected based on the observation.>

**Proof of Concept:**
<Exact commands used with full flags, proxy settings, and authentication context. Must be copy-paste reproducible.>

**Result:**
<What happened. Include relevant HTTP responses, shell output, or evidence. Direct, no fluff.>

**Business Impact:**
<Real-world consequence: data exposure, account takeover, infrastructure compromise, compliance violation.>

**Remediation:**
<Specific, actionable fix. Code-level or config-level. Reference vendor docs or security standards.>

---
<Repeat for each finding, sorted by severity descending>

## Attack Chain Summary
<If findings were chained, show the full path: Finding A -> Finding B -> Objective achieved>

## Techniques Mapped
| # | Technique | MITRE ATT&CK | OWASP | Finding Ref |
|---|-----------|--------------|-------|-------------|

## Appendix
- Tools used with versions
- Scan timestamps
- Scope boundaries respected
```

### Report Structure for CTF:

```markdown
# Walkthrough: <Platform> - <Name>
**Date:** <date>
**Objective:** <flags, root, etc.>

## Reconnaissance
<What was discovered and how. Name tools, commands, key output.>

## Exploitation Path

### Step <N>: <Action Name>
**Technique:** MITRE ATT&CK: <Tactic> / <Technique ID> - <Technique Name>

**Discovery:**
<How this vector was identified. What signal led here.>

**Reasoning:**
<Why this action was chosen over alternatives.>

**Command:**
<Exact command, copy-paste ready with full context.>

**Result:**
<Output and evidence. Direct.>

---
<Repeat for each step in the kill chain>

## Flags
- User: <flag>
- Root: <flag>

## Techniques Mapped
| # | Technique | MITRE ATT&CK | Step Ref |
|---|-----------|--------------|----------|
```

## 4. Lesson Extraction
After generating the report, extract lessons for the Global Brain:
1. Review findings for novel techniques, bypasses, or mistakes.
2. **Dedup check:** `grep -i "<key_term>" {LEARNINGS}/<domain>.md`
3. Append new lessons using enriched tag format:
   `echo "#Tag1 #Tag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: X -> Solution: Y" >> {LEARNINGS}/<domain>.md`

## 5. Output
`[REPORT GENERATED] See <platform>/<client>/report.md. Lessons extracted: <count> entries to {LEARNINGS}/<domain>.md.`
