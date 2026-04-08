# TKS Fleet Configuration

This file is auto-inherited by all agents in subdirectories. Keep it lean — every token here is loaded on every turn for every agent.

## Fleet Paths (Single Source of Truth)

When you see `{PLAYBOOKS}`, `{LEARNINGS}`, or `{TOOLS}` in agent configs or skills, expand to these paths in all generated bash commands:

| Reference | Path |
|---|---|
| `{PLAYBOOKS}` | `$HOME/Pentester/tksClaudeAgent/Playbooks` |
| `{LEARNINGS}` | `$HOME/Pentester/tksClaudeAgent/learnings` |
| `{TOOLS}` | `$HOME/Pentester/ptTools` |

To move the fleet to a different system, update ONLY this table.

## Agent-to-Playbook Mapping

| Agent | Primary Playbook Dirs | Learnings File |
|---|---|---|
| bountyHunter | Web/ | web.md |
| webApiPen | Web/ | web.md |
| netPen | AD/, Windows/, Pivoting/, C2/ | network.md |
| cloudPen | Cloud/ | cloud.md |
| ctfPlayer | ALL (cross-domain) | ctf.md |
| tksButler | ALL (orchestrator) | general.md |

## Reactive Playbook Lookup (Proposal Loop Integration)

When you discover new services, ports, technologies, or attack paths during an engagement:

1. Identify signals (e.g., port 88 → Kerberos, port 445 + signing disabled → relay, JWT in response → token attacks)
2. `grep -i "<signal>" {PLAYBOOKS}/<relevant_category>/INDEX.md`
3. For matching techniques, check the **Prereq** column — do you have what's needed?
4. If prerequisites are met, read ONLY the matched technique from the full Playbook file
5. Factor the technique into your Threat Model and Proposal — cite the Playbook source

This lookup is part of the Proposal Loop. Do it EVERY time you observe something new, not just during /robin.

## Playbook Entry Format

Every Playbook technique entry MUST follow this structure (enforced by `/absorb`):

```
### Technique Name [added: YYYY-MM]
- **Tags:** #Primary1 #Primary2 #Alias1 #Alias2 #Alias3
- **Trigger:** <what observations should lead an agent here>
- **Prereq:** <what you must have before this works>
- **Yields:** <what you get if successful>
- **Opsec:** Low | Med | High
- **Context:** <when/why to use this>
- **Payload/Method:** <commands>
```

## Output Token Discipline

Every character an agent outputs costs output tokens. ALL agents MUST minimize unnecessary output:

- **Never print file diffs, full file contents, or line-by-line change summaries.** The changes are on disk — the user can read them.
- **Never echo back what was added or removed.** Just confirm the action: "Updated X" or "Done."
- **Never restate the user's request** before acting on it.
- **Status updates:** Use counts and file names only, not content. E.g., "Enriched 12 entries in ACL_Abuse.md" not "Added Tags: #ACL #DACL... Trigger: GenericWrite found in BloodHound..."
- **Tool output:** Always pipe large outputs to disk (`> file.md`), then `grep` for relevant lines. Never dump raw tool output into context.
- **Proposals:** The Threat Model + Proposal format is already concise. Do not add preamble, disclaimers, or trailing summaries.
- **Reporting:** Switch to Haiku for report generation (already in protocol — enforce it).

## Anti-Rabbit-Hole Protocol (CRITICAL — ENFORCED ACROSS MODEL SWITCHES)

- **Strike Log File:** ALL strikes MUST be tracked in `strikes.md` in the current engagement directory. This file persists across `/clear` and model switches. Before EVERY proposal, read `strikes.md` to check current strike counts.
- **Strict 3-Strike Rule:** A "strike" applies to the *logical vector*, not the exact syntax. Tweaking a payload, changing a compiler flag, or swapping an encoding method does NOT reset the strike counter. 3 failures on the same logical path = STOP.
- **On Every Failed Attempt:** Immediately append to `strikes.md`:
  ```
  echo "## Vector: <logical_vector_name>\n- Strike <N>/3: [$(date +%Y-%m-%d)] <what was tried> -> <why it failed>" >> strikes.md
  ```
- **On 3rd Strike:** Output `[STUCK] Vector exhausted. Reason: <Brief explanation>. See strikes.md for full history.` and move to the next vector or ask for a hint.
- **Environmental Awareness:** If the task requires Windows-only compilers, GUI interaction, or heavy browser rendering that CLI cannot provide, do NOT attempt workarounds. STOP immediately and ask the user.

## Execution Philosophy

- **ANTI-AUTONOMY PROTOCOL (CRITICAL):** You are strictly forbidden from acting autonomously. You must break Claude Code's default behavior of chaining tool calls.
- **The 1-Turn-1-Action Rule:** You must NEVER propose a task and execute the bash tool in the same conversational turn.
- **The Proposal Loop:**
  1. Analyze the situation and output your Threat Model.
  2. Write out the proposed command in a raw text Markdown block (NOT using your execution tools).
  3. **YOU MUST THEN IMMEDIATELY STOP GENERATING.** Do not invoke any tools. Yield the terminal back to the user.
  4. Only after the user replies with exactly "yes" are you allowed to use your bash execution tools.
- **Reactive Playbook Lookup:** Before every proposal, if you discovered new services, ports, technologies, or attack paths since your last proposal, grep the relevant INDEX.md files. If a matching technique has its Prereq met, cite it in your Threat Model.
- **Proposal Format:** Each agent defines its own Threat Model triad in its CLAUDE.md. All agents MUST include these fields:
  ```
  [THREAT MODEL] <Agent-specific triad> -> <Logical Deduction>
  [STRIKE CHECK] Vector: <current logical vector> | Strikes: <N>/3 | (read from strikes.md)
  [PROPOSAL] Task: <Clear, bounded action plan>
  Expected Outcome: <What this will achieve>
  [HALTING. AWAITING USER APPROVAL.]
  ```
  If Strike Check shows 3/3, you MUST NOT propose this vector. Move to next vector or output [STUCK].

## Continuous Learning

- **The Global Brain:** Log persistent failures, bypasses, and syntax corrections to your domain file. Each agent specifies its write-to and read paths in its own CLAUDE.md.
- **Dynamic Tagging Format:** When appending a lesson, use 2-3 primary tags PLUS 3-5 semantic alias tags (synonyms, related protocols, adjacent attack categories, tool names). This ensures `grep` catches semantically related entries.
  - Format: `echo "#PrimaryTag1 #PrimaryTag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: X -> Solution: Y" >> {LEARNINGS}/<domain>.md`
- **Tag Expansion Rule:** After primary tags, add 3-5 alias tags covering: synonyms, related protocols, attack category, tool names, and adjacent techniques.
- **Contextual Retrieval:** NEVER `cat` the entire file. Use `grep -i` with dynamic keywords.
  - Single domain: `grep -i "<keyword>" {LEARNINGS}/<domain>.md`
  - Cross-domain: `grep -ri "<keyword>" {LEARNINGS}/`

## Reporting Protocol

- When a vulnerability or objective is achieved, you MUST NOT generate the report automatically.
- Instead, propose it so the user can attempt further chaining or switch to a cheaper/faster model (like Haiku) for writing.
- **Lesson Extraction Rules:**
  - Lessons MUST be **universal** — applicable to any future engagement, not tied to a specific target.
  - Use tags: `#mistake`, `#hallucination`, `#waf-loop`, `#rabbit-hole`, `#technique`, `#bypass` as appropriate.
  - Format: `echo "#Tag1 #Tag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: <what went wrong/was discovered> -> Solution: <universal takeaway>" >> {LEARNINGS}/<domain>.md`
  - **Tag Expansion Rule:** After primary tags, add 3-5 alias tags. BAD: too few tags (searching related terms won't find it). GOOD: primary + alias tags covering synonyms, tools, protocols, attack categories.
  - **Reporting Tip:** Switch to Haiku model before typing 'yes' to save tokens on report generation.
