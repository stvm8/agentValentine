# Reconnaissance & Enumeration

## Source Code Analysis
- Android app leaks Cognito Identity Pool ID in source: `us-east-1:d2fecd68-ab89-48ae-b70f-44de60381367`
- App uses unauthenticated (guest) Cognito access
- Targets: S3 `hl-app-images`, Lambda `Tracking`

## Cognito Identity Pool Abuse
- Identity ID obtained: `us-east-1:6391d33c-4b11-cbae-a4f2-0f326c52178f`
- Assumed role: `arn:aws:sts::427648302155:assumed-role/Cognito_StatusAppUnauth_Role/CognitoIdentityCredentials`
- Account ID: `427648302155`

## S3 Enumeration (s3://hl-app-images)
```
2023-07-15 12:52:13       4052 hl.png
2023-07-15 13:10:54          0 temp/
2023-07-15 13:11:22       3428 temp/id_rsa   <-- BREAK GLASS CREDS
```

## Lambda
- Function `Tracking` exists — `GetFunctionConfiguration` denied for unauth role
- `InvokeFunction` allowed (per app source)

## Denied Actions
- `lambda:GetFunctionConfiguration`
- `cognito-identity:DescribeIdentityPool`
