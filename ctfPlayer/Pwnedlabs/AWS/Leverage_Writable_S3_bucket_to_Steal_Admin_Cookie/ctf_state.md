# Lab State: Leverage Writable S3 Bucket to Steal Admin Cookie

**Status:** COMPLETED ✓
**Date:** 2026-04-05
**Platform:** Pwnedlabs
**Target:** 10.1.20.25

## Flags Captured
- **Flag 1 (Unintended):** `8e685ca5924cbe9d3cd27efcd29d8763` — extracted from `/8e685ca5924cbe9d3cd27efcd29d8763.xlsx` (world-readable on web root)
- **Flag 2 (Intended):** Admin session `PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8` — captured via S3 supply chain XSS

## Key Credentials Captured
| Username | Password | Type |
|----------|----------|------|
| marco | hlpass99 | SSH/Web (given) |
| jsmith | Pass1234! | AD |
| svc_awsS3 | S3$Svc2023 | AWS IAM |
| sdas | Sdas$2023 | Jenkins admin |
| (27 more) | (see loot.md) | Multi-cloud service accounts |

## Intended Attack Chain (Successfully Executed)
1. ✓ Nmap + SSH recon (marco credentials)
2. ✓ Source code review → S3 bucket identified
3. ✓ /opt enumeration → Selenium bot (HeadlessChrome) confirmed
4. ✓ S3 bucket write test → world-writable confirmed
5. ✓ Backup original bootstrap.min.js
6. ✓ Craft XHR payload (prepended)
7. ✓ Upload poisoned asset to S3
8. ✓ Start nc listener on target localhost:8000
9. ✓ Capture admin cookie (~70s)
10. ✓ Replay cookie → authenticated /home.php access
11. ✓ Restore original asset (cleanup)

## Lessons Learned (Documented in agent_learnings.md)
- [AWS][S3][XSS] Always enumerate /opt before payload deployment
- [AWS][S3][XSS] Prepend payloads, don't append
- [AWS][S3][XSS] Determine exfil direction from bot location (localhost vs. attacker IP)

## Files Generated
- `Walkthrough_Leverage_Writable_S3_Bucket.md` — Full 0xdf-style writeup
- `loot.md` — Credentials + methodology notes
- `creds.md` — User/password table
- `scans.md` — Enumeration data
- `network_topology.md` — Architecture notes
