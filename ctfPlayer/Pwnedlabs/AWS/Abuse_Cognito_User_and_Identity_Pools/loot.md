# Loot

## Break Glass Credentials — SSH Private Key
- **Source**: `s3://hl-app-images/temp/id_rsa`
- **Access Vector**: Unauthenticated Cognito Identity Pool -> `Cognito_StatusAppUnauth_Role` -> `s3:GetObject`
- **Key Type**: OpenSSH RSA 4096-bit
- **File**: `id_rsa` (chmod 600)

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA8Mf+UZVrD5/PY/js0V3sH4JxaPCQTU9FUeTQwOtjw56ATrMoocS5
...RSA 4096 bit key...
-----END OPENSSH PRIVATE KEY-----
```

## Flag
`0ae8d66db969a8f7880b123070b7f2f9`

## Break Glass Account (Plaintext in PDF)
- **Username**: breakglass_admin
- **Password**: @!HugeLogisticsPassword123!
- **Document**: AWS Disaster Recovery Plan (hl-status-log-bucket/IT-Temp/)
