# Scope

**Platform:** Pwnedlabs  
**Challenge:** Uncover Secrets in CodeCommit and Docker  
**Given:** https://hub.docker.com/search  
**Objective:** Capture flag.txt content  
**Date:** 2026-04-05  

## Notes
- Entry point: Docker Hub search
- Key technologies: AWS CodeCommit, Docker/Docker Hub
- Likely vector: Public Docker image containing secrets (hardcoded creds, .git history, CodeCommit credentials)
