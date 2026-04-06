# Scans

## Nmap — 10.129.230.70 (2026-04-01)

**Domain:** king.htb | **Hostname:** OPENAD | **OS:** Windows (DC)

| Port  | Service         | Notes |
|-------|----------------|-------|
| 22    | SSH (Win 7.7)  | Lateral movement option |
| 53    | DNS            | Standard DC |
| 80    | IIS 10.0       | Default page |
| 88    | Kerberos       | DC confirmed |
| 389/3268 | LDAP        | king.htb |
| 445   | SMB            | Signing required |
| 5985  | WinRM          | Shell target post-exploit |
| **8161** | **Jetty (ActiveMQ Web)** | **401 Basic Auth — ActiveMQRealm** |
| 8530/8531 | IIS 10.0  | **WSUS** |
| **61616** | **ActiveMQ OpenWire 5.18.2** | **CVE-2023-46604 RCE** |

## Critical Findings
- **CVE-2023-46604**: Apache ActiveMQ 5.18.2 is VULNERABLE (patched in 5.18.3)
  - RCE via ClassPathXmlApplicationContext on port 61616
- **ActiveMQ console** on 8161 — try default creds admin:admin
- **WSUS** on 8530 — secondary pivot if needed
