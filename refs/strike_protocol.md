# Strike Protocol

## Definition
A strike applies to the **logical vector** — the goal being attempted — not the specific command or tool.
Switching tools, changing encodings, or tweaking payloads does NOT reset the counter.

## Environmental Prerequisites
If a vector requires solving an environmental problem first (OCR, missing compiler, GUI dependency),
that prerequisite counts toward strikes on the parent vector. Two environmental failures = abandon the vector.

## On Each Failure
Immediately append to `strikes.md`:
```
echo "## Vector: <name>\n- Strike <N>/3: [$(date +%Y-%m-%d)] <tried> -> <why failed>" >> strikes.md
```

## On 3rd Strike
Output: `[STUCK] Vector exhausted. Reason: <brief>. See strikes.md.`
Then move to next vector or ask for a hint. No exceptions.

## Examples of Same Logical Vector
- Manual OCR → ImageMagick → tesseract → row-normalization: all one vector ("read CAPTCHA")
- PATCH with role=admin → PATCH with role=editor: same vector ("escalate via PATCH")
- SQLi with ' → SQLi with ') → SQLi with 1=1: same vector ("SQL injection on param X")
