---
description: Absorb knowledge from a URL, writeup, or file and inject the hacking techniques into the Global Brain.
---
I am calling the `/absorb` skill to process external knowledge.
**Source to Absorb:** $ARGUMENTS

**Task:**
1. **Source Ingestion:** 
   - If it's a URL (blog/writeup), use `curl -sL` or your built-in fetch tools to download the text. (Strip HTML tags if necessary using `sed` or `awk` to save tokens).
   - If it's a local file (`.pdf`, `.docx`, `.txt`), use your file-reading tools or CLI utilities (like `pdftotext` or `cat`) to read it safely.
   - *Note on YouTube:* If it's a YouTube URL, inform me that you cannot watch video and ask me to provide the transcript or paste the key notes.

2. **Analysis & Extraction:** Act as a Senior Security Researcher. Analyze the text and ignore all fluff, introductory paragraphs, and generic definitions. Extract ONLY:
   - Novel exploit chains or logic flaws.
   - WAF/EDR bypass techniques.
   - Specific tool syntax or custom payloads that solve a unique problem.

3. **Global Brain Injection:** Convert the extracted techniques into our standardized learning format and append them to the Global Brain. 
   - You MUST use this exact format for each discrete lesson:
     `echo "[Tag1][Tag2] Issue/Context: <The scenario or roadblock> -> Solution/Technique: <The specific payload or methodology>" >> $HOME/Pentester/AI_Teams/agent_learnings.md`
   - Create as many `echo` commands as necessary to capture all the unique techniques in the source.

4. **Summary Report:** Output a `[🧠 KNOWLEDGE ABSORBED]` block summarizing the specific techniques you successfully extracted and injected into the Global Brain.
