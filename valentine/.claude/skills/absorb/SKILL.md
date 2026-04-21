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
6. **Summary:** Output a `[KNOWLEDGE ABSORBED]` block listing: files created/updated in Playbooks, INDEX rows added, entries skipped (duplicates), and total new techniques added.
