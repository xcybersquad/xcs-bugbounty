# xcs-bugbounty
The XCS Bug Bounty Toolkit is an all-in-one automation framework for security researchers. It combines recon, subdomain discovery, port scanning, OSINT, vulnerability detection (SQLi, XSS, CSRF), and reporting into one script. Supports Nmap, Nuclei, Golismero, Dirsearch, Holehe, h8mail, PhoneInfoga, and more.





# XCS Bug Bounty Toolkit

The **XCS Bug Bounty Toolkit** is an all-in-one automation framework for reconnaissance, vulnerability scanning, OSINT, and reporting.  
It integrates popular bug bounty and OSINT tools into a single script to simplify your workflow.  

## ✨ Features
- Subdomain enumeration with status code detection  
- Port scanning, OS detection, and vulnerability checks (Nmap)  
- Vulnerability scanning with **Nuclei**, **Golismero**, and other tools  
- SQLi, XSS, and CSRF parameter discovery  
- Hidden directory discovery  
- Real IP and WHOIS information  
- Email & phone number OSINT using **Holehe, h8mail, PhoneInfoga**  
- Automated reporting in **Markdown, HTML, and PDF**  
- Interactive **menu-driven** mode and **CLI mode**  

## 🚀 Quick Start
Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/xcs-bugbounty-full.git
cd xcs-bugbounty-full
chmod +x xcs-bugbounty-full.sh
./xcs-bugbounty-full.sh
use bash or ./ command 

# OUTPUT >>

=============================================
   XCS Bug Bounty Toolkit - v1.0
   Recon • Exploit • OSINT • Reporting
   Company: XCS Security Labs
=============================================

[+] Starting Recon on: example.com
---------------------------------------------
[*] Subdomain Discovery (subfinder + httpx)
   - api.example.com [200]
   - dev.example.com [403]
   - test.example.com [301]

[*] Port Scanning (nmap)
   - api.example.com: 22/tcp open (ssh)
   - api.example.com: 443/tcp open (https)
   - dev.example.com: 80/tcp open (http)
   - test.example.com: 3306/tcp open (mysql) → POTENTIAL RISK

[*] Directory Brute-force (dirsearch)
   - /admin (403 Forbidden)
   - /login (200 OK)
   - /uploads (200 OK)

[*] Vulnerability Scanning (nuclei + golismero)
   - api.example.com → CVE-2023-XXXX [High]
   - dev.example.com → Reflected XSS found at /search?q=
   - test.example.com → SQLi possible at /products?id=

[*] Email/Phone OSINT
   - user@example.com → Found on LinkedIn, 2 breaches (pwned DBs)
   - +91XXXXXXXXXX → Found in spam dataset, flagged on Truecaller

[*] WHOIS & Real IP Lookup
   - Registrar: NameCheap
   - Real IP: 192.0.2.45 (Cloudflare masked)

[*] Suspicious/Phishing Check
   - test.example.com → Potential malware hosting

---------------------------------------------
[+] Report Generated: reports/example_report.pdf
   - High: 2
   - Medium: 3
   - Low: 1
   - Informational: 5
=============================================

