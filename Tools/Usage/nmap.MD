| Purpose                                        | Syntax                                                             |
|------------------------------------------------|--------------------------------------------------------------------|
| Perform a full port scan and service version detection on multiple hosts | `nmap --unprivileged -sV -p 1-65535 -oA full_scan_results -iL addresses.txt` |
| Scan a single host                             | `nmap 192.168.1.1`                                                 |
| Scan multiple IP addresses                     | `nmap 192.168.1.1 192.168.1.2 192.168.1.3`                         |
| Perform a stealth scan (SYN scan)              | `nmap -sS 192.168.1.1`                                             |
| Detect OS and services                         | `nmap -A 192.168.1.1`                                              |
| Save scan results in XML format                | `nmap -oX scan_results.xml 192.168.1.1`                            |
