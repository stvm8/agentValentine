# CTF State — Abuse_Cognito_User_and_Identity_Pools

## Platform: Pwnedlabs
## Status: OBJECTIVE ACHIEVED

## Attack Chain
1. Extracted Cognito Identity Pool ID from Android app source code
2. Called `cognito-identity:GetId` (no auth) -> got Identity ID
3. Called `cognito-identity:GetCredentialsForIdentity` -> got temp AWS creds
4. Assumed role: `Cognito_StatusAppUnauth_Role`
5. Enumerated S3 bucket `hl-app-images` -> found `temp/id_rsa`
6. Downloaded SSH RSA 4096-bit private key = **break glass credentials**

## Key Artifacts
- `id_rsa` — SSH private key (break glass creds)
- `creds.md` — Cognito temp credentials
- `loot.md` — Full loot details

## FINAL STATUS: COMPLETE — PWNED

## Break Glass Credentials
- Username: breakglass_admin
- Password: @!HugeLogisticsPassword123!

## Flag: 0ae8d66db969a8f7880b123070b7f2f9
