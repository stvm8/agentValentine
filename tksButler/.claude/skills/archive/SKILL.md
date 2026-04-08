---
description: Archive a completed engagement — extract lessons, summarize, and move to _archive/. (e.g., /archive engagement: ClientX)
disable-model-invocation: true
---
I am executing the `/archive` command.
**Arguments:** $ARGUMENTS

Parse the arguments for: `engagement:` (required), `agent:` (optional — which agent directory).

## 1. Locate Engagement
Navigate to the engagement directory. If `agent:` is provided, look in that agent's directory. Otherwise, search across all agent directories.

## 2. Extract Lessons Learned
Review the engagement files and extract key learnings:
1. Read `vulnerabilities.md` / `findings/` for confirmed findings
2. Read state files for the Reasoning Log sections
3. Read `creds.md` for credential patterns worth noting
4. Identify any novel techniques, bypasses, or tool usage patterns

For each lesson worth preserving:
- Determine the correct domain file (`learnings/web.md`, `learnings/cloud.md`, `learnings/network.md`, `learnings/ctf.md`, or `learnings/general.md`)
- **Dedup check:** `grep -i "<key_term>" {LEARNINGS}/<domain>.md` before appending
- Append using the enriched tag format: `echo "#PrimaryTag1 #PrimaryTag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: X -> Solution: Y" >> {LEARNINGS}/<domain>.md`
- **Tag Expansion Rule:** After 2-3 primary tags, add 3-5 semantic alias tags (synonyms, related protocols, adjacent attack categories, tool names). This ensures `grep` catches semantically related entries even when searching by different terminology.

## 3. Generate Engagement Summary
Create `_summary.md` in the engagement directory with:
- **Engagement:** Name, dates, scope
- **Key Findings:** Brief list of confirmed vulnerabilities with severity
- **Techniques Used:** What worked and what didn't
- **Lessons Extracted:** Which entries were added to the Global Brain
- **Statistics:** Number of findings by severity, time spent per phase

## 4. Archive
Move the engagement directory to `_archive/<agent>/<engagement>/`:
`mkdir -p _archive/<agent> && mv <engagement_path> _archive/<agent>/`

## 5. Output
Output a `[📦 ARCHIVED]` block containing:
- Number of lessons extracted and which domain files were updated
- Archive location
- Engagement summary highlights

## Rules
- NEVER delete engagement files — move them to _archive/
- ALWAYS extract lessons before archiving — this is the primary purpose
- Check for duplicates before appending to learnings files
- If the engagement has no findings, still archive with a summary noting "no confirmed findings"
