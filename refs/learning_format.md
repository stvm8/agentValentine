# Learning Format

## Before Appending — Dedup Check (mandatory)
```bash
grep -i "<key_term>" {LEARNINGS}/<domain>.md
```
If a matching entry exists, update it in place. Never append a duplicate.

## Append Format
```bash
echo "#PrimaryTag1 #PrimaryTag2 #Alias1 #Alias2 #Alias3 [$(date +%Y-%m-%d)] Issue: <what happened> -> Solution: <universal takeaway>" >> {LEARNINGS}/<domain>.md
```

## Tag Rules
- 2-3 primary tags + 3-5 alias tags covering: synonyms, related protocols, tool names, attack categories.
- Lessons must be universal — applicable to any future engagement, not tied to a specific target.
- Use tags: `#mistake`, `#hallucination`, `#waf-loop`, `#rabbit-hole`, `#technique`, `#bypass`, `#privesc`

## Example
```
#CAPTCHA #FormRecon #OCR #WebForm #Registration #rabbit-hole [2026-04-26] Issue: Submitted wrong field names (user[name] instead of user[username]) causing 500 before CAPTCHA was even tested -> Solution: Always fetch and parse form HTML for exact field names before any POST; never assume.
```
