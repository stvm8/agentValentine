---
title: bountyTemplate
tags: #bountyHunter
created: 2026-04-05
modified: 2026-04-05
type: note
---

# Report: Vulnerability Type on Vulnerable URL/Endpoint

**Program:** Target Program
**Severity:** Critical (P1) / High (P2)
**Vulnerability Type:** e.g., SQL Injection, SSRF, BOLA, Auth Bypass
**Endpoint:** `e.g., https://api.target.com/v1/users/update`

---

## Description
Provide a concise, 2-3 sentence explanation of the vulnerability. Example: "The `avatar_url` parameter on the `/v1/users/update` endpoint does not properly validate user input or restrict internal routing. This allows an attacker to supply a local AWS metadata IP, resulting in Server-Side Request Forgery (SSRF) that leaks internal cloud credentials."

---

## Impact
Explain the worst-case scenario business impact. Triagers use this to justify the bounty payout. Example: "An unauthenticated attacker can retrieve temporary AWS STS credentials for the EC2 role, allowing them to assume the role, access internal S3 buckets, and potentially pivot to full infrastructure compromise."

---

## Steps to Reproduce
Provide a numbered, step-by-step guide to reproducing the exploit. Assume the triager is testing this from scratch. If authentication is required, state how to get the token.

1. Navigate to `URL or Application Feature`.
2. Authenticate as a Privilege Level user and intercept the traffic using Caido/Burp Suite.
3. Trigger the `Specific Action` feature to generate the following HTTP Request:

```http
Insert the exact, unmodified RAW HTTP Request here. Include all necessary headers, cookies, and the injected payload.
```

4. Send the request. Observe the application's behavior. 
5. (Optional) If OOB (Out of Band) interaction is required, note that a ping will be received at the attacker's Interactsh/Collaborator server.

---

## Proof of Concept (PoC)
Show the exact HTTP Response from the server proving the exploit was successful, or the exact `curl` command the triager can run to verify it.

**HTTP Response:**
```http
Insert the RAW HTTP Response showing the leaked data, bypassed auth, or successful SQL execution.
```

**cURL Reproduction Command:**
```bash
Insert a ready-to-use curl command containing the payload so the triager can verify it from their terminal in 5 seconds.
```

---

## Remediation
Provide 1-2 sentences of actionable advice for the developers. Example: "Implement an allowlist of permitted domains for the webhook feature. Block requests to internal IP ranges (169.254.169.254, 10.0.0.0/8, 127.0.0.1) and disable following redirects."
