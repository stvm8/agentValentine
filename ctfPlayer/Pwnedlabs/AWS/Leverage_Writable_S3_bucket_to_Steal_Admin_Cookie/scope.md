# Scope

**Platform:** Pwnedlabs
**Challenge:** Leverage Writable S3 Bucket to Steal Admin Cookie
**Given:** 10.1.20.25
**Objective:** Access a sensitive credentials file — capture the flag within it
**Date:** 2026-04-05

## Notes
- Entry point: Web app at 10.1.20.25
- Vector: Writable AWS S3 bucket → XSS/content injection → Admin cookie theft → Credentials file
