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
| Tools for scraping, such as Amass, Subfinder, BBOT                                                                                                                      | Amass, Subfinder, BBOT                                                         |
| Service Enumeration and Version Detection                                                                                                                      | [Use](https://github.com/ashtonhogan/hack-the-planet/blob/main/Tools/Usage/nmap.md) nmap to detect service versions.                                                         |
| Checking for Misconfigurations                                                                                                                      | Visit HTTP/HTTPS pages for default pages or error messages. [Use](https://github.com/ashtonhogan/hack-the-planet/blob/main/Tools/Usage/gobuster.md) tools like gobuster with pre-built [payloads](https://github.com/payloadbox/directory-payload-list/tree/master/Intruder) to find hidden directories and files.                                                         |
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
| 80, 443     | **SSL/TLS Configuration and Security**: Use `sslscan <target-ip>:443` or `testssl.sh` to check for weak ciphers, outdated protocols, and certificate issues.                                      |
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

#### Testing known Vulnerabilities

| Vulnerability                                                                | Description                                                                                           |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| [Array Index Underflow (CWE-129)](https://cwe.mitre.org/data/definitions/129.html)     | Accessing array elements using an index that is less than zero.                                       |
| [Classic Buffer Overflow (CWE-120)](https://cwe.mitre.org/data/definitions/120.html)   | Overwriting memory by writing more data than a buffer can hold.                                       |
| [Buffer Over-read (CWE-126)](https://cwe.mitre.org/data/definitions/126.html)          | Reading more data than intended from a buffer.                                                        |
| [Buffer Underflow (CWE-124)](https://cwe.mitre.org/data/definitions/124.html)          | Reading before the beginning of a buffer.                                                             |
| [Buffer Under-read (CWE-127)](https://cwe.mitre.org/data/definitions/127.html)         | Accessing data before the start of a buffer.                                                          |
| [Cleartext Storage of Sensitive Information (CWE-312)](https://cwe.mitre.org/data/definitions/312.html) | Storing sensitive information without encryption.                                      |
| [Cleartext Transmission of Sensitive Information (CWE-319)](https://cwe.mitre.org/data/definitions/319.html) | Transmitting sensitive data without encryption.                                      |
| [CRLF Injection (CWE-93)](https://cwe.mitre.org/data/definitions/93.html)              | Inserting CRLF sequences into headers or logs to manipulate them.                                      |
| [Cross-site Scripting (XSS) - Reflected (CWE-79)](https://cwe.mitre.org/data/definitions/79.html) | Injecting malicious scripts into a web application that reflects input.                               |
| [Cross-site Scripting (XSS) - Stored (CWE-79)](https://cwe.mitre.org/data/definitions/79.html) | Injecting malicious scripts into a web application that stores input.                                |
| [Deserialization of Untrusted Data (CWE-502)](https://cwe.mitre.org/data/definitions/502.html) | Deserializing data from untrusted sources, leading to code execution.                                 |
| [Double Free (CWE-415)](https://cwe.mitre.org/data/definitions/415.html)               | Freeing memory that has already been freed.                                                            |
| [Heap Overflow (CWE-122)](https://cwe.mitre.org/data/definitions/122.html)             | Overwriting memory in the heap segment.                                                               |
| [Improper Access Control - Generic (CWE-284)](https://cwe.mitre.org/data/definitions/284.html) | Failing to enforce proper authorization controls.                                        |
| [Improper Certificate Validation (CWE-295)](https://cwe.mitre.org/data/definitions/295.html) | Not properly validating certificates, leading to man-in-the-middle attacks.                         |
| [Improper Following of a Certificate's Chain of Trust (CWE-296)](https://cwe.mitre.org/data/definitions/296.html) | Not properly verifying the certificate chain of trust.                                     |
| [Improper Null Termination (CWE-170)](https://cwe.mitre.org/data/definitions/170.html) | Failing to null-terminate strings, leading to memory corruption.                                      |
| [Inadequate Encryption Strength (CWE-326)](https://cwe.mitre.org/data/definitions/326.html) | Using weak encryption algorithms or insufficient key lengths.                                      |
| [Incorrect Calculation of Buffer Size (CWE-131)](https://cwe.mitre.org/data/definitions/131.html) | Miscalculating buffer size, leading to buffer overflows.                                     |
| [Insecure Direct Object Reference (IDOR) (CWE-639)](https://cwe.mitre.org/data/definitions/639.html) | Allowing unauthorized access to objects via direct references.                                      |
| [Integer Overflow (CWE-190)](https://cwe.mitre.org/data/definitions/190.html)          | Allowing an integer to exceed its maximum value, causing unexpected behavior.                         |
| [Integer Underflow (CWE-191)](https://cwe.mitre.org/data/definitions/191.html)         | Allowing an integer to go below its minimum value, causing unexpected behavior.                       |
| [Key Exchange without Entity Authentication (CWE-322)](https://cwe.mitre.org/data/definitions/322.html) | Performing key exchange without verifying the identity of the entities involved.            |
| [Man-in-the-Middle (CWE-300)](https://cwe.mitre.org/data/definitions/300.html)         | Intercepting and altering communication between two parties.                                          |
| [Missing Required Cryptographic Step (CWE-325)](https://cwe.mitre.org/data/definitions/325.html) | Omitting necessary steps in a cryptographic process.                                     |
| [NULL Pointer Dereference (CWE-476)](https://cwe.mitre.org/data/definitions/476.html)  | Dereferencing a pointer that has not been initialized.                                                |
| [Off-by-one Error (CWE-193)](https://cwe.mitre.org/data/definitions/193.html)          | Accessing memory one position before or after an intended buffer.                                     |
| [OS Command Injection (CWE-78)](https://cwe.mitre.org/data/definitions/78.html)        | Injecting and executing arbitrary OS commands.                                                        |
| [Out-of-bounds Read (CWE-125)](https://cwe.mitre.org/data/definitions/125.html)        | Reading data outside the boundaries of an array.                                                      |
| [Password in Configuration File (CWE-260)](https://cwe.mitre.org/data/definitions/260.html) | Storing plaintext passwords in configuration files.                                      |
| [Path Traversal (CWE-22)](https://cwe.mitre.org/data/definitions/22.html)              | Accessing files outside the intended directory using relative paths.                                  |
| [Plaintext Storage of a Password (CWE-256)](https://cwe.mitre.org/data/definitions/256.html) | Storing passwords in plaintext, making them easily accessible.                                      |
| [Privacy Violation (CWE-359)](https://cwe.mitre.org/data/definitions/359.html)         | Exposing personal or sensitive information.                                                           |
| [Remote File Inclusion (CWE-98)](https://cwe.mitre.org/data/definitions/98.html)       | Including remote files through external inputs, leading to code execution.                            |
| [Resource Injection (CWE-99)](https://cwe.mitre.org/data/definitions/99.html)          | Injecting external resources into a program.                                                          |
| [Reusing a Nonce, Key Pair in Encryption (CWE-323)](https://cwe.mitre.org/data/definitions/323.html) | Reusing nonces or key pairs in cryptographic processes.                                    |
| [Reversible One-Way Hash (CWE-328)](https://cwe.mitre.org/data/definitions/328.html)   | Using weak hashing algorithms that can be reversed.                                                   |
| [Security Through Obscurity (CWE-656)](https://cwe.mitre.org/data/definitions/656.html) | Relying on secret or hidden elements for security.                                      |
| [Session Fixation (CWE-384)](https://cwe.mitre.org/data/definitions/384.html)          | Fixing a session ID, allowing attackers to hijack user sessions.                                      |
| [Stack Overflow (CWE-121)](https://cwe.mitre.org/data/definitions/121.html)            | Overwriting the stack by writing more data than it can hold.                                          |
| [Storing Passwords in a Recoverable Format (CWE-257)](https://cwe.mitre.org/data/definitions/257.html) | Storing passwords in a format that can be easily reversed.                                |
| [Type Confusion (CWE-843)](https://cwe.mitre.org/data/definitions/843.html)            | Accessing a resource using an incompatible type.                                                      |
| [Use After Free (CWE-416)](https://cwe.mitre.org/data/definitions/416.html)            | Accessing memory after it has been freed.                                                             |
| [Use of a Broken or Risky Cryptographic Algorithm (CWE-327)](https://cwe.mitre.org/data/definitions/327.html) | Using deprecated or insecure cryptographic algorithms.                                    |
| [Use of a Key Past its Expiration Date (CWE-324)](https://cwe.mitre.org/data/definitions/324.html) | Using cryptographic keys beyond their intended lifetime.                                  |
| [Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) (CWE-338)](https://cwe.mitre.org/data/definitions/338.html) | Using PRNGs that do not provide adequate randomness.                                  |
| [Use of Hard-coded Credentials (CWE-798)](https://cwe.mitre.org/data/definitions/798.html) | Embedding credentials directly in the code.                                              |
| [Use of Hard-coded Cryptographic Key (CWE-321)](https://cwe.mitre.org/data/definitions/321.html) | Embedding cryptographic keys directly in the code.                                        |
| [Use of Hard-coded Password (CWE-259)](https://cwe.mitre.org/data/definitions/259.html) | Embedding passwords directly in the code.                                                |
| [Use of Inherently Dangerous Function (CWE-242)](https://cwe.mitre.org/data/definitions/242.html) | Using functions that are dangerous or insecure by design.                                 |
| [Use of Insufficiently Random Values (CWE-330)](https://cwe.mitre.org/data/definitions/330.html) | Using random values that are not adequately unpredictable.                                |
| [Weak Cryptography for Passwords (CWE-261)](https://cwe.mitre.org/data/definitions/261.html) | Using weak or easily cracked encryption for passwords.                                     |
| [Wrap-around Error (CWE-128)](https://cwe.mitre.org/data/definitions/128.html)         | Allowing an integer to wrap around, causing unexpected behavior.                                      |
| [Write-what-where Condition (CWE-123)](https://cwe.mitre.org/data/definitions/123.html) | Writing data to an unintended location in memory.                                                     |
| [Use of Externally-Controlled Format String (CWE-134)](https://cwe.mitre.org/data/definitions/134.html) | Using format strings that can be controlled by external input.                             |
| [Information Exposure Through an Error Message (CWE-209)](https://cwe.mitre.org/data/definitions/209.html) | Revealing sensitive information through error messages.                                    |
| [Information Exposure Through Debug Information (CWE-215)](https://cwe.mitre.org/data/definitions/215.html) | Revealing sensitive information through debug data.                                       |
| [Missing Encryption of Sensitive Data (CWE-311)](https://cwe.mitre.org/data/definitions/311.html) | Transmitting or storing data without encryption.                                          |
| [Forced Browsing (CWE-425)](https://cwe.mitre.org/data/definitions/425.html)           | Accessing parts of a web application without proper authorization.                                    |
| [HTTP Request Smuggling (CWE-444)](https://cwe.mitre.org/data/definitions/444.html)    | Interfering with the way a server processes HTTP requests.                                             |
| [Insufficiently Protected Credentials (CWE-522)](https://cwe.mitre.org/data/definitions/522.html) | Not adequately protecting stored credentials.                                               |
| [Unprotected Transport of Credentials (CWE-523)](https://cwe.mitre.org/data/definitions/523.html) | Transmitting credentials without adequate protection.                                     |
| [Information Exposure Through Directory Listing (CWE-548)](https://cwe.mitre.org/data/definitions/548.html) | Exposing sensitive files through directory listings.                                     |
| [Insufficient Session Expiration (CWE-613)](https://cwe.mitre.org/data/definitions/613.html) | Allowing sessions to remain active too long, risking hijacking.                          |
| [Unverified Password Change (CWE-620)](https://cwe.mitre.org/data/definitions/620.html) | Allowing password changes without proper verification.                                    |
| [Weak Password Recovery Mechanism for Forgotten Password (CWE-640)](https://cwe.mitre.org/data/definitions/640.html) | Using easily bypassed methods for password recovery.                               |
| [Improper Neutralization of HTTP Headers for Scripting Syntax (CWE-644)](https://cwe.mitre.org/data/definitions/644.html) | Failing to properly encode or sanitize HTTP headers.                                    |
| [XML Entity Expansion (CWE-776)](https://cwe.mitre.org/data/definitions/776.html)      | Expanding XML entities in a way that causes excessive resource consumption.                        |
| [Reliance on Cookies without Validation and Integrity Checking in a Security Decision (CWE-784)](https://cwe.mitre.org/data/definitions/784.html) | Using cookies for security decisions without validation.                                    |
| [LDAP Injection (CWE-90)](https://cwe.mitre.org/data/definitions/90.html)              | Injecting malicious LDAP queries.                                                                     |
| [XML Injection (CWE-91)](https://cwe.mitre.org/data/definitions/91.html)               | Injecting malicious XML code.                                                                         |
| [Cross-site Scripting (XSS) - DOM (CWE-79)](https://cwe.mitre.org/data/definitions/79.html) | Manipulating the DOM to execute malicious scripts.                                                  |
| [Improper Authentication - Generic (CWE-287)](https://cwe.mitre.org/data/definitions/287.html) | Failing to properly authenticate users.                                                  |
| [Command Injection - Generic (CWE-77)](https://cwe.mitre.org/data/definitions/77.html) | Injecting and executing arbitrary OS commands.                                                        |
| [Cross-Site Request Forgery (CSRF) (CWE-352)](https://cwe.mitre.org/data/definitions/352.html) | Forcing users to execute unwanted actions through their authenticated sessions.              |
| [Cryptographic Issues - Generic (CWE-310)](https://cwe.mitre.org/data/definitions/310.html) | General weaknesses in cryptographic implementations.                                     |
| [Uncontrolled Resource Consumption (CWE-400)](https://cwe.mitre.org/data/definitions/400.html) | Allowing uncontrolled use of resources, leading to DoS.                                   |
| [HTTP Response Splitting (CWE-113)](https://cwe.mitre.org/data/definitions/113.html)   | Splitting HTTP responses by injecting CRLF sequences.                                               |
| [Information Disclosure (CWE-200)](https://cwe.mitre.org/data/definitions/200.html)    | Exposing sensitive information to unauthorized users.                                                  |
| [Memory Corruption - Generic (CWE-119)](https://cwe.mitre.org/data/definitions/119.html) | General memory corruption vulnerabilities.                                                   |
| [Violation of Secure Design Principles (CWE-657)](https://cwe.mitre.org/data/definitions/657.html) | Failing to follow secure design principles.                                              |
| [Privilege Escalation (CAPEC-233)](https://capec.mitre.org/data/definitions/233.html)  | Gaining higher privileges than intended.                                                               |
| [Code Injection (CWE-94)](https://cwe.mitre.org/data/definitions/94.html)              | Injecting and executing arbitrary code.                                                               |
| [Server-Side Request Forgery (SSRF) (CWE-918)](https://cwe.mitre.org/data/definitions/918.html) | Manipulating a server to make requests to unintended locations.                         |
| [SQL Injection (CWE-89)](https://cwe.mitre.org/data/definitions/89.html)               | Injecting malicious SQL queries.                                                                      |
| [UI Redressing (Clickjacking) (CAPEC-103)](https://capec.mitre.org/data/definitions/103.html) | Tricking users into clicking on hidden elements.                                         |
| [Open Redirect (CWE-601)](https://cwe.mitre.org/data/definitions/601.html)             | Redirecting users to unintended URLs.                                                                 |
| [XML External Entities (XXE) (CWE-611)](https://cwe.mitre.org/data/definitions/611.html) | Exploiting XML parsers to execute malicious code.                                        |
| [Improper Restriction of Authentication Attempts (CWE-307)](https://cwe.mitre.org/data/definitions/307.html) | Allowing unlimited authentication attempts, risking brute-force attacks.                 |
| [Business Logic Errors (CWE-840)](https://cwe.mitre.org/data/definitions/840.html)     | Exploiting flaws in the business logic of an application.                                             |
| [Malware (CAPEC-549)](https://capec.mitre.org/data/definitions/549.html)               | Deploying malicious software to compromise systems.                                                   |
| [Phishing (CAPEC-98)](https://capec.mitre.org/data/definitions/98.html)                | Tricking users into revealing sensitive information.                                                  |
| [Insecure Storage of Sensitive Information (CWE-922)](https://cwe.mitre.org/data/definitions/922.html) | Storing sensitive data without proper security measures.                                  |
| [Client-Side Enforcement of Server-Side Security (CWE-602)](https://cwe.mitre.org/data/definitions/602.html) | Relying on client-side mechanisms for security enforcement.                             |
| [Leftover Debug Code (Backdoor) (CWE-489)](https://cwe.mitre.org/data/definitions/489.html) | Leaving debug code or backdoors in production software.                                    |
| LLM01: Prompt Injection | Manipulating prompts to execute unintended actions in LLMs. |
| LLM02: Insecure Output Handling | Failing to properly sanitize or handle outputs from LLMs. |
| LLM03: Training Data Poisoning | Corrupting training data to affect LLM behavior. |
| LLM04: Model Denial of Service | Overloading an LLM to cause denial of service. |
| LLM05: Supply Chain Vulnerabilities | Exploiting weaknesses in the supply chain of LLM components. |
| LLM06: Sensitive Information Disclosure | Causing LLMs to reveal sensitive or confidential information. |
| LLM07: Insecure Plugin Design | Designing plugins for LLMs with insecure practices. |
| LLM08: Excessive Agency | Allowing LLMs too much control or decision-making power. |
| LLM09: Overreliance | Relying too heavily on LLMs without adequate oversight. |
| LLM10: Model Theft | Stealing or replicating LLM models without authorization. |
