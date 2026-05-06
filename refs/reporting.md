# Reporting Protocol

## When to Report
When a vulnerability or objective is achieved, do NOT auto-generate the report.
Propose it — let the user attempt further chaining or switch to Haiku for writing.

## Lesson Extraction
Before generating any report, extract universal lessons to the domain learnings file.
Follow format in `refs/learning_format.md`.

## Report Generation
Switch to Haiku model before running `/report` to save tokens.
Use Haiku for all report writing — it is cheaper and fast enough for structured output.

## Content Quality (mandatory)
Before writing any learning or playbook entry, read `refs/content_quality.md`.
All entries must be portable — no target names, IPs, or client-specific paths.

## Playbook Entry Format (for /absorb)
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
