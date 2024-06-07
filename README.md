![Hack The Planet](https://github.com/ashtonhogan/hack-the-planet/blob/main/giphy.gif?raw=true)

## Index

- [Education](Education/README.md)
- [Tools](Tools/README.md)
	- [Gobuster Usage](Tools/Usage/gobuster.md)
	- [Metasploit Framework Usage](Tools/Usage/metasploitframework.md)
	- [Nmap Usage](Tools/Usage/nmap.md)
	- [Sublist3r Usage](Tools/Usage/sublist3r.md)
	
## Methodology

### 1. Recon

| Description                                                                                                                                                             | Link                                                                                   |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Used to find autonomous system numbers which are used to group a company's public IP addresses                                                                         | [BGP Toolkit](https://bgp.he.net/)                                                     |
| Used to find additional IP addresses that belong to the company                                                                                                         | [ARIN Whois](https://whois.arin.net/ui/query.do)                                       |
| Used to find information about company acquisitions and other related data                                                                                              | [Crunchbase](https://www.crunchbase.com/)                                              |
| Used to find journalism material about a company, including additional assets and shares, or other companies it owns                                                    | [Aleph](https://aleph.occrp.org)                                                       |
| AI tools for asking about company acquisitions                                                                                                                          | ChatGPT / Claude / Gemini                                                              |
| Get a list of tools that the site was built with and find their ad analytics code and all the domains that share the same code                                          | [BuiltWith](https://builtwith.com/)                                                    |
| Search engine to find IP, Port, Certificate information, links to favicons and images hosted on admin panels or private servers, and websites being hosted on IPv6      | [Shodan](https://www.shodan.io/)                                                       |
| Tool to parse data from Shodan                                                                                                                                          | [Karma v2](https://github.com/Dheerajmadhukar/karma_v2)                                |
| Obtain the domains and subdomains from the Shodan dataset                                                                                                               | [Shosubgo](https://github.com/incogbyte/shosubgo)                                      |
| Reverse Whois to find out all the sites that a company owns                                                                                                             | [Whoxy](https://whoxy.com)                                                             |
| Scans cloud IP ranges and provides a report of addresses that responded with a certificate on port 443 (indicating it has a website)                                    | [Cloud IP Range Scanner](https://kaeferjaeger.gay/?dir=sni-ip-ranges)                  |
| Git subdomains discovery                                                                                                                                               | [Git Subdomains](https://github.com/)                                                  |
| Git analysis                                                                                                                                                           | [Git Analysis](https://github.com/)                                                    |
| Tools for scraping, such as nmap, Amass, Subfinder, BBOT                                                                                                                      | nmap, Amass, Subfinder, BBOT                                                         |
| Linked Discovery integration with Burp Suite                                                                                                                           | Linked Discovery -> Burp                                                               |
| Bruteforce subdomain discovery                                                                                                                                          | Bruteforce                                                                             |
| Domain permutations for subdomain discovery                                                                                                                            | Permutations                                                                           |
| HTTPX tool for probing URLs and taking screenshots                                                                                                                     | [HTTPX](https://github.com/projectdiscovery/httpx)                                      |
| Common Vulnerabilities and Exposures (CVE) database                                                                                                                     | [CVE Database](https://www.cvedetails.com/cve/CVE-2009-5016/)                          |
| CVSS v3 Vulnerability Scoring Calculator                                                                                                                               | [CVE Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)                 |

### 2. Hacking 🏴‍☠️

#### Testing open ports

Check the [pentest wiki](https://github.com/nixawk/pentest-wiki/blob/master/3.Exploitation-Tools/Network-Exploitation/ports_number.md) for services commonly running on each port.

| Port Number | Actions and Common Vulnerabilities                                                                                                                                                                  |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 80, 443     | - **Service Enumeration and Version Detection**: Use `nmap -sV -p 80,443 <target-ip>` to detect service versions.                                                                                   |
|             | - **Checking for Misconfigurations**: Visit HTTP/HTTPS pages for default pages or error messages. Use tools like `gobuster` to find hidden directories and files.                                   |
|             | - **SSL/TLS Configuration and Security**: Use `sslscan <target-ip>:443` or `testssl.sh` to check for weak ciphers, outdated protocols, and certificate issues.                                      |
|             | - **Vulnerability Scanning**: Run tools like `Nikto`, `OpenVAS`, or `Nessus` to find known vulnerabilities.                                                                                         |
|             | - **Web Application Testing**: Perform manual and automated tests using tools like `OWASP ZAP` and `Burp Suite` to check for vulnerabilities like SQL injection, XSS, CSRF, and file inclusion.      |
|             | - **Exploitation (if permitted)**: Search for public exploits with `searchsploit nginx <version>`, and consider creating custom exploits if necessary.                                              |
|             | - **Privilege Escalation**: Look for server misconfigurations, files with incorrect permissions, and attempt to upload web shells if possible.                                                      |
|             | - **Reporting**: Document findings, provide detailed reports, and give remediation recommendations.                                                                                                |
|             | - **Common Vulnerabilities**: Default pages, directory listing, weak SSL/TLS configurations, SQL injection, XSS, CSRF, file inclusion, and outdated software vulnerabilities.                       |
| 443         | - **SSL/TLS Configuration and Security**: Assess SSL/TLS strength using `sslscan <target-ip>:443` or `testssl.sh`.                                                                                  |
|             | - **Checking for Misconfigurations**: Look for weak ciphers, outdated protocols, and certificate issues.                                                                                            |
|             | - **Common Vulnerabilities**: Weak ciphers, outdated protocols, self-signed certificates, and SSL/TLS misconfigurations.                                                                            |
| 80          | - **Service Enumeration and Version Detection**: Use `nmap -sV -p 80 <target-ip>` to detect service versions.                                                                                        |
|             | - **Checking for Misconfigurations**: Visit HTTP pages for default pages or error messages. Use tools like `gobuster` to find hidden directories and files.                                          |
|             | - **Common Vulnerabilities**: Default pages, directory listing, exposed configuration files, and outdated software vulnerabilities.                                                                 |
| Any Port    | - **Service Enumeration and Version Detection**: Use `nmap -sV -p <port> <target-ip>` to identify services and versions.                                                                            |
|             | - **Automated Vulnerability Scanning**: Use tools like `OpenVAS`, `Nessus`, or `Nikto` to scan for vulnerabilities.                                                                                 |
|             | - **Manual Testing**: Manually test identified services for vulnerabilities specific to the detected service (e.g., FTP, SSH, SMTP).                                                                |
|             | - **Privilege Escalation**: Look for misconfigurations, incorrect file permissions, and other weaknesses that could allow privilege escalation.                                                     |
|             | - **Common Vulnerabilities**: Service-specific vulnerabilities (e.g., outdated software, misconfigurations, weak passwords, open directories), and privilege escalation opportunities.              |
