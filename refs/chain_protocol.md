# Chain Protocol

## What a Chain Is
An ordered tree of attack nodes where each confirmed finding may unlock one or more next steps. Chains maximize impact by combining individual findings. Every node retains its standalone severity — the chain only adds value on top, never removes it.

## When Valentine Uses This
After confirming any finding, run:
```
grep -ri "<technique_keyword>" /Volumes/tksmac/Pentester/tksClaudeAgent_dev/Playbooks/CHAINS/
```
If a match is found, surface the chain as a **single proposal** at the end of the current action — never mid-execution. User approves before Valentine pursues any chain node.

## Chain File Format

```markdown
# Chain: <Name>
Tags: <comma-separated keywords for grep>
Chain Severity: <Critical|High|Medium>
Entry Condition: <what must be confirmed to enter this chain>

## Node N — <Label>
Technique: [[<Dir>/<Playbook>]]
Strike Vector: "<named vector string — must match strikes.md entry>"
Condition: <what must be true to attempt this node>
Standalone Severity: <Critical|High|Medium|Low>
Branches:
  - <condition> → Node N+1
  - <condition> → [[Chain: <other-chain-file>]] Node N+1
  - <condition> → [TERMINAL] <finding label>
```

## Node Field Rules
- **Technique:** wikilink to the playbook entry. Obsidian graph view auto-renders this.
- **Strike Vector:** the logical vector name used in `strikes.md`. Strikes are tracked per node, not per chain. A chain entry point succeeding = zero strikes on that node.
- **Condition:** the observable that must be true before attempting this node. If unverifiable, it's a prereq gap — surface as a proposal item, not an assumption.
- **Standalone Severity:** the severity of this finding in isolation, reported in `vulnerabilities.md` the moment it's confirmed regardless of chain outcome.
- **Branches:** ordered by impact (highest first). Valentine proposes the highest-impact viable branch. Branch conditions are observed facts, not guesses.

## Strike Accounting
- Confirming a node = success. Zero strikes consumed on that node.
- Failing to advance from a node = strike on that node's Strike Vector.
- 3 strikes on a Strike Vector = [STUCK] on that branch. Document node finding, check remaining branches.
- A failed branch does not consume strikes on sibling branches — each branch is an independent vector.

## Branch Switching
Valentine does NOT auto-switch chains. If a branch is [STUCK]:
1. Record the node's standalone finding in `vulnerabilities.md`.
2. Check if the failure revealed a new observable (e.g., internal service exposed while probing cloud metadata).
3. If yes → surface as a new proposal: "Node X is [STUCK], but observed Y — entry point for [[Chain: other-chain]]."
4. Stop. User decides.

## Severity Escalation Rules
- Chain Severity applies only when ALL non-terminal nodes in the primary branch complete.
- Partial chain (1–2 nodes confirmed, chain broken): report each node at its Standalone Severity. No chain severity bump.
- Full chain: report the final node at Chain Severity, note the full path in `vulnerabilities.md`.

## Proposal Format for Chain Opportunities
Append to the standard proposal block:
```
[CHAIN OPPORTUNITY] Chain: <name> | Entry: <confirmed node> | Next: <Node label>
Chain Severity if complete: <severity>
Next node condition: <observable required>
```

## Adding New Chains
1. Create `Playbooks/CHAINS/<descriptive-name>.md` using the format above.
2. Use actual playbook filenames as wikilinks — verify the file exists before writing.
3. Add entry to `Playbooks/CHAINS/INDEX.md`.
4. Update `CHANGELOG.md`.
