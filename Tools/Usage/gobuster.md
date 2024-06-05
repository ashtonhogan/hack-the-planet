| Purpose                                       | Syntax                                                |
|-----------------------------------------------|-------------------------------------------------------|
| Directory brute-force attack                  | `gobuster dir -u https://example.com -w wordlist.txt` |
| Force-disable wildcard responses              | `gobuster dir -u https://example.com -w wordlist.txt -z` |
| Perform subdomain brute-forcing               | `gobuster dns -d example.com -w subdomains.txt`       |
| Set the number of concurrent threads         | `gobuster dir -u https://example.com -w wordlist.txt -t 50` |
| Exclude status codes from the output          | `gobuster dir -u https://example.com -w wordlist.txt -s 404,500` |
| Use specific HTTP methods for requests        | `gobuster dir -u https://example.com -w wordlist.txt -x .php,.html -m GET,POST` |
