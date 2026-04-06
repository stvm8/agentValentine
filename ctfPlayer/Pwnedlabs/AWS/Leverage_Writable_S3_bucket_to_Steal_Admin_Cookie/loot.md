# Loot

## Flag

| Flag | Source |
|------|--------|
| `8e685ca5924cbe9d3cd27efcd29d8763` | /8e685ca5924cbe9d3cd27efcd29d8763.xlsx — last row labeled "flag" (directly accessible, no auth required) |

## Intended Attack Vector — S3 Supply Chain XSS (Incomplete)

### Kill Chain
1. S3 bucket `frontend-web-assets-8deaf0c2d067` is publicly writable (anonymous PUT, no auth)
2. `admin.php` and `home.php` both load `/assets/bootstrap.min.js` from the bucket — no SRI integrity check
3. Overwrite `bootstrap.min.js` with original content + appended IIFE payload
4. Admin bot visits page → poisoned JS executes in admin browser context → cookie exfiltrated
5. Replay stolen `PHPSESSID` against `home.php` → authenticated admin access

### What Was Done
- Downloaded clean `bootstrap.js` (50564 bytes) as `bootstrap.min.js.bak` (true original backup)
- Built trojanized `bootstrap.min.js`: original Bootstrap 4.0.0-beta.2 + S3 self-exfil payload appended before sourcemap line
- Payload: `fetch PUT` of `document.cookie` + `location.href` to `s3://frontend-web-assets-8deaf0c2d067/loot/c_<random>.txt`
- Uploaded successfully — live in S3, confirmed via curl tail check

### Exfil Attempts
| Method | Result | Reason |
|--------|--------|--------|
| `Image()` beacon → `http://10.8.0.9:80` (VPN) | No hits | Lab VM cannot reach attacker VPN — outbound blocked |
| `fetch PUT` → S3 bucket `loot/` | No hits after 3 min | Admin bot mechanism unclear — no JS execution confirmed |

### Result — PWNED
- Cookie captured at poll 7 (~70s after upload)
- `PHPSESSID=sbfe3uhqftpkiksu8mju74rhm8` — HeadlessChrome/120.0.6099.216 (Selenium bot on server)
- Replayed cookie → `home.php` returned **"Welcome Admin!"** with Export/Import user panel

### Cleanup
- `bootstrap.min.js.bak` restored to S3 via `aws s3 cp` ✓

---

## Sensitive Data — Credentials Spreadsheet (8e685ca5924cbe9d3cd27efcd29d8763.xlsx)

| Username / Account | Password | Notes |
|---|---|---|
| jsmith | Pass1234! | Main AD account |
| svc_azureDB | svc$AzureDB#2023 | Azure SQL Service Principal |
| aroberts | Summer2023# | Office365 |
| IAM_Logistics | Log$AWSsvc2023 | AWS IAM for Logistics App |
| cfernandez | Charlie$567 | GCP Compute Engine |
| svc_gcpStorage | Gcp#Stor$2023 | GCP Cloud Storage Service Account |
| knguyen | Kings@2023 | |
| svc_awsRDS | Rds#Svc$2023 | AWS RDS Service Principal |
| ltaylor | Taylor$2023# | Azure VM login |
| IAM_Billing | Bill@IAM2023 | AWS IAM for Billing Analysis |
| sdas | Sdas$2023 | Jenkins admin |
| svc_azureBlob | Blob!Svc#2023 | Azure Blob Storage Service Principal |
| gjones | Spring#2023 | Local machine admin |
| IAM_Reporting | Report$IAM23 | AWS IAM for BI Reporting |
| vpatel | Vp#2023Azure | AWS EC2 instance |
| svc_gcpVM | VMgcp@Svc2023 | GCP VM Service Account |
| llewis | Lewis#2023! | Azure Kubernetes |
| svc_dockerReg | Docker$Svc23 | Docker Registry Service Account |
| wthomas | Thom@AWS23 | GitHub |
| IAM_DevOps | DevOps#IAM23 | AWS IAM for CI/CD Pipelines |
| sscott | Scott$2023# | Bitbucket |
| svc_awsLambda | Lambda!Svc23 | AWS Lambda Service Principal |
| acampbell | Cam@AWS23 | |
| svc_gcpFunc | Func$GcpSvc23 | GCP Functions Service Account |
| klopez | KLop#Azure23 | Azure Blob Storage |
| svc_awsS3 | S3$Svc2023 | AWS S3 Service Principal |
| flag | 8e685ca5924cbe9d3cd27efcd29d8763 | Flag row |
