---
description: Absorb a writeup/blog/file, extract the hacking techniques, and save them to the Playbooks.
---
I am calling the `/absorb` skill to process external knowledge.
**Source to Absorb:** $ARGUMENTS

**Task:**
1. **Source Ingestion:** Use `curl -sL` (for URLs) or file-reading tools (for local PDFs/TXTs) to read the source. Strip HTML/fluff to save tokens.
2. **Extraction:** Analyze the text. Extract ONLY novel exploit chains, bypasses, and specific tool payloads. Ignore generic definitions.
3. **Dedup Check:** Before saving, `grep -i "<technique_key_terms>" <target_playbook_file>`. If a substantially similar entry already exists, SKIP it or UPDATE the existing entry with new details rather than duplicating.
4. **Categorize & Save:** Inject these techniques into the Hierarchical Knowledge Base.
   - Determine the Category (e.g., `Web`, `AD`, `Cloud`, `Linux`, `Windows`, `Pivoting`, `C2`) and Topic (e.g., `SSRF`, `Kerberoasting`).
   - Create the directory if it doesn't exist: `mkdir -p {PLAYBOOKS}/<Category>`
   - Append the technique using the enriched format (see root CLAUDE.md for full spec):
     ```
     echo -e "\n### <Technique Name> [added: $(date +%Y-%m)]\n- **Tags:** #Primary1 #Primary2 #Alias1 #Alias2 #Alias3\n- **Trigger:** <what observation leads here>\n- **Prereq:** <what you need>\n- **Yields:** <what you get>\n- **Opsec:** Low|Med|High\n- **Context:** <Scenario>\n- **Payload/Method:** <Command>" >> {PLAYBOOKS}/<Category>/<Topic>.md
     ```
   - **Tags:** 2-3 primary tags + 3-5 semantic alias tags (synonyms, related protocols, tool names, adjacent techniques)
   - **Trigger:** What an agent would observe during an engagement that should lead to this technique
   - **Prereq:** What you must already have (creds, access level, vulnerability type)
   - **Yields:** What a successful execution produces (shells, hashes, tokens, access)
   - **Opsec:** Detection risk level (Low/Med/High)
   - **Date Stamp:** Every `###` line MUST include `[added: YYYY-MM]` with the current month
5. **INDEX.md Update:** After writing the entry, append a row to `{PLAYBOOKS}/<Category>/INDEX.md`:
   ```
   echo "| <Technique Name> | <Topic>.md | <Trigger summary> | <Prereq summary> | <Yields summary> | <Opsec> | <space-separated tags> |" >> {PLAYBOOKS}/<Category>/INDEX.md
   ```
6. **_FLOW.md Update:** For each new technique saved, update the category's `_FLOW.md` if one exists (e.g., `{PLAYBOOKS}/Cloud/_FLOW.md`).
   - Read the existing `_FLOW.md` to identify which stage the technique belongs to based on its Prereq and Trigger (match against stage signal descriptions).
   - `grep -i "<technique_name>" {PLAYBOOKS}/<Category>/_FLOW.md` — if already present, skip.
   - If not present, append a new row to the correct stage's table:
     ```
     | <Technique Name> | <Topic>.md | <Key Prereq — one phrase> | <Yields — one phrase> |
     ```
   - If no existing stage fits (new access level or attack surface), append a new stage block at the end of the file following the same heading/table/`→ Next:` format.
   - If no `_FLOW.md` exists for the category, skip this step.

7. **Chain Detection + Chain File Update:** Re-read the source narrative as a whole. If 2+ extracted techniques form a confirmed sequence (A enabled B, B enabled C as described in the writeup):
   ```
   grep -i "<entry_technique_keyword>" {PLAYBOOKS}/CHAINS/INDEX.md
   ```
   - **Match found (live chain — no `[CANDIDATE]` prefix):** Read the matching chain file. Check if the sequence from this writeup adds a new node, branch, or condition not already covered. If yes, edit the chain file in place to add the node/branch. If already covered, skip.
   - **Match found (CANDIDATE row):** Skip — chain file does not exist yet; user must approve first.
   - **No match:** Append a candidate row to `{PLAYBOOKS}/CHAINS/INDEX.md`:
     ```
     | [CANDIDATE] <Chain Name> | <slug>.md | <entry technique> | <Node1> → <Node2> → <Node3> | <Critical/High/Medium> | <source URL or filename> |
     ```
     Do NOT create the chain file. User reviews `CHAINS/INDEX.md` and approves when ready.
   - **Single technique only:** Skip chain detection entirely.
   - **_FLOW.md chain reference:** After any chain action (new candidate row OR live chain update), also update `_FLOW.md` for the relevant category:
     - Identify the stage whose Signal matches the chain's entry point.
     - `grep -i "<chain_slug>" {PLAYBOOKS}/<Category>/_FLOW.md` — if already referenced, skip.
     - If not present, append the chain reference to that stage's `→ Next:` line:
       ```
       | Full chain: [[<slug>]] — <one-line summary of the full sequence>
       ```
       Append it as a new `| Full chain: ...` line directly after the existing `→ **Next:**` line, before the `---` separator. Use `[CANDIDATE]` prefix in the slug reference if the chain is not yet approved (e.g., `[[CANDIDATE: <slug>]]`).

8. **Summary:** Output a single line to context only:
   `[ABSORBED] <N> techniques → <files updated> | _FLOW.md: <stages updated or "no change"> | <chain updates or candidate rows added>`
