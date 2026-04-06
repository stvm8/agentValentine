---
description: Absorb a writeup/blog/file, extract the hacking techniques, and save them to the Playbooks.
---
I am calling the `/absorb` skill to process external knowledge.
**Source to Absorb:** $ARGUMENTS

**Task:**
1. **Source Ingestion:** Use `curl -sL` (for URLs) or file-reading tools (for local PDFs/TXTs) to read the source. Strip HTML/fluff to save tokens.
2. **Extraction:** Analyze the text. Extract ONLY novel exploit chains, bypasses, and specific tool payloads. Ignore generic definitions.
3. **Categorize & Save:** Inject these techniques into the Hierarchical Knowledge Base. 
   - Determine the Category (e.g., `Web`, `AD`, `Cloud`, `PrivEsc`) and Topic (e.g., `SSRF`, `Kerberoasting`).
   - Create the directory if it doesn't exist: `mkdir -p $HOME/Pentester/AI_Teams/Playbooks/<Category>`
   - Append the technique using this format:
     `echo -e "\n### <Technique Name>\n- **Context:** <Scenario>\n- **Payload/Method:** <Command>" >> $HOME/Pentester/AI_Teams/Playbooks/<Category>/<Topic>.md`
4. **Summary:** Output a `[🧠 KNOWLEDGE ABSORBED]` block listing the files you created/updated in the Playbooks directory.
