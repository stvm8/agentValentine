# TKS Fleet Configuration

## Fleet Paths
| Reference | Path |
|-----------|------|
| `{PLAYBOOKS}` | `/path/to/Playbooks` |
| `{LEARNINGS}` | `/path/to/learnings` |
| `{TOOLS}` | `/path/to/tools` |

## Agent-to-Playbook Mapping
| Agent | Engagement Type | Playbook Dirs | Learnings |
|-------|----------------|--------------|-----------|
| valentine | webapp / api | Web/ | web.md |
| valentine | network | AD/, Windows/, Pivoting/, C2/, Linux/ | network.md |
| valentine | cloud | Cloud/ | cloud.md |
| valentine | ctf | ALL | ctf.md |
| moosey | bug bounty (webapp / api) | Web/ | bounty.md + web.md |

## Hard Rules (enforced across all agents and model switches)
- **Strike Rule:** Read `strikes.md` before EVERY proposal. Strike = logical vector failure, not syntax. 3 strikes = [STUCK]. Full protocol: `refs/strike_protocol.md`.
- **Anti-Autonomy:** Never propose and execute in the same turn. Proposal → STOP → wait for "yes" → execute. Full format: `refs/proposal_format.md`.
- **Changelog:** Update `CHANGELOG.md` at root (MM/DD/YYYY | file | description) after any change to CLAUDE.md files, skill files, or playbook INDEX files.
- **Output Discipline:** Pipe all large outputs to disk. Never dump raw tool output into context. Never echo file diffs or content back.
- **Learning Dedup:** Grep learnings before appending. Update in place if match found. Full format: `refs/learning_format.md`.
- **ROE:** See `refs/roe.md`. Core: no DoS, no brute force, no destructive SQL, no data exfil.
