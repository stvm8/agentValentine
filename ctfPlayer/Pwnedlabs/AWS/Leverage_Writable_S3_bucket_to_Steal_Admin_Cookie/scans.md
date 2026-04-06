# Scans & Enumeration

## Nmap Results (2026-04-05)
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
80/tcp open  http    Apache httpd 2.4.41
  Title: Huge Logistics
```

## Web App Files (/var/www/html/)
- index.php — public landing page
- admin.php — login page (uses config.php for credentials)
- home.php — admin dashboard (requires $_SESSION['Active'] == true)
- contact_me.php — contact form
- config.php — credentials config (permission denied to marco)

## S3 Findings
- Bucket: frontend-web-assets-8deaf0c2d067.s3.amazonaws.com
- Access: **Publicly WRITABLE** (anonymous PUT allowed)
- Contents: bootstrap.min.css, font-awesome.min.css, jquery-3.7.0.min.js, bootstrap.min.js, agency.min.js, contact_me.js, images
- Attack surface: All JS/CSS on both index.php and admin.php/home.php loaded from this bucket

## Key Endpoints
- /admin.php — login page
- /home.php — admin panel (session-protected)
- /8e685ca5924cbe9d3cd27efcd29d8763.xlsx — credentials spreadsheet (PUBLICLY ACCESSIBLE, no auth required)
