# Nmap 7.98 scan initiated Wed Apr  1 10:59:25 2026 as: /usr/lib/nmap/nmap --privileged -sV -sC -p- --min-rate 5000 -oN /home/takashi/Pentester/AI_Teams/ctfPlayer/HTB/OpenAD/nmap.md 10.129.230.70
Nmap scan report for king.htb (10.129.230.70)
Host is up (0.029s latency).
Not shown: 65508 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:4a:4e:19:cd:15:53:4f:48:d3:ab:04:83:13:8e:3c (RSA)
|   256 80:e0:d6:85:fc:16:22:03:b3:68:3c:3b:87:86:dc:68 (ECDSA)
|_  256 07:88:e2:6e:77:a7:4a:97:37:d4:5f:02:31:8a:3a:cb (ED25519)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-01 15:59:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: king.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: king.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8161/tcp  open  http          Jetty
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
8530/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49888/tcp open  msrpc         Microsoft Windows RPC
49908/tcp open  msrpc         Microsoft Windows RPC
61616/tcp open  apachemq      ActiveMQ OpenWire transport 5.18.2
Service Info: Host: OPENAD; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -8s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-04-01T16:00:45
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Apr  1 11:01:33 2026 -- 1 IP address (1 host up) scanned in 128.10 seconds
