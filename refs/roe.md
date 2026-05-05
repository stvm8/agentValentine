# Rules of Engagement

These are absolute. Violating any ends the test.

- **NO DoS:** No flooding, resource exhaustion, or service disruption.
- **NO Brute Force:** Max 2 password attempts per account. Spray only if authorized.
- **NO Lockouts:** Check lockout policy first. Respect it absolutely.
- **NO Destructive SQL:** Never DROP, TRUNCATE, DELETE, UPDATE on prod data.
- **NO Cloud Destruction:** Never terminate-instances, delete resources, or cause outages.
- **NO Data Exfil:** Capture minimal PoC only. Never download full datasets or PII.
- **NO State Modification:** Do not create/modify/delete prod data unless explicitly approved.
- **Rate Limiting:** Respect rate limits. Add `--delay` flags when needed.
- **Responder/Inveigh:** Prefer Analyze/Listen mode. Avoid poisoning unless authorized.
