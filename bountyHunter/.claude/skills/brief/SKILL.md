---
description: Load a massive ROE file, lock in strict constraints, and generate a 1-target Game Plan.
tags: [#bountyHunter]
---
I am executing the `/brief` command.
**Target File:** $ARGUMENTS

Execute the following sequence strictly:
1. **Read ROE:** Read the specified file (e.g., `ROE.md`) in its entirety.
2. **Acknowledge Rules:** Output a strict confirmation that you understand the "Out of Scope" and "What You Cannot Do" rules. Acknowledge any mandatory HTTP headers required (e.g., `X-Bug-Bounty`).
3. **Game Plan Creation:** Do NOT attack everything at once. Analyze the "In Scope" list and select exactly **ONE** high-value logical target (e.g., a specific API endpoint or a single wildcard domain) to begin with.
4. **Execution:** Output your first `[⚡ PROPOSAL]` outlining a step-by-step recon and exploitation plan for ONLY that single target, ensuring all planned actions comply perfectly with the ROE.
