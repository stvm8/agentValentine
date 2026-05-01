# CHAINS Index

| Chain | File | Entry Point | Sequence | Chain Severity | Source |
|-------|------|-------------|----------|---------------|--------|
| [[ssrf-cloud-tenant]] | ssrf-cloud-tenant.md | SSRF on cloud-hosted target | SSRF → Cloud Metadata → IAM PrivEsc → Full Tenant | Critical | manual |
| [[ssrf-internal-pivot]] | ssrf-internal-pivot.md | SSRF with RFC1918 internal response | SSRF → Internal Service → RCE → Lateral Movement | Critical | manual |
| [[ntlm-relay-domain-takeover]] | ntlm-relay-domain-takeover.md | SMB signing disabled / coercion available | NTLM Relay → Cred Dump → DCSync → Domain Takeover | Critical | manual |
| [[azure_blob_to_keyvault]] | azure_blob_to_keyvault.md | Anonymous $web blob listing on Azure Static Website | Anonymous Blob Enum → Cred Zip Download → az CLI Auth → Key Vault ACL Bypass (AzureServices) → Secrets Exfil | High | Azure Blob Container to Initial Access/genNotes.md |
| [[azure_recon_to_kudu_dbexfil]] | azure_recon_to_kudu_dbexfil.md | Target company domain known; employee names + leaked password findable | EntraID Recon → Subdomain Enum (azsubenum) → Name Harvest → UPN Spray → az CLI Auth → Website Contributor → Kudu SCM Shell → DB Creds in Scripts → SQL Exfil | High | Azure Recon to Foothold and Profit/genNotes.md |
