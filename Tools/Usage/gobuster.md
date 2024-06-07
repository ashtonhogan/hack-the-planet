| Purpose                                       | Syntax                                                |
|-----------------------------------------------|-------------------------------------------------------|
| Directory brute-force attack                  | `gobuster dir -u https://example.com -w wordlist.txt` |
| Force-disable wildcard responses              | `gobuster dir -u https://example.com -w wordlist.txt -z` |
| Perform subdomain brute-forcing               | `gobuster dns -d example.com -w subdomains.txt`       |
| Set the number of concurrent threads         | `gobuster dir -u https://example.com -w wordlist.txt -t 50` |
| Exclude status codes from the output          | `gobuster dir -u https://example.com -w wordlist.txt -s 404,500` |
| Use specific HTTP methods for requests        | `gobuster dir -u https://example.com -w wordlist.txt -x .php,.html -m GET,POST` |

#### Using gobuster with nmap results

##### Step 1

Extract the IP list from `full_scan_results.gnmap`: 

```
Host: 192.168.0.1 ()	Ports: 80/open/tcp//http//TLB/, 443/open/tcp//ssl|https//TLB/	Ignored State: filtered (65533)
```

Reformat it into `input.txt`:

```
192.168.0.1:80
192.168.0.1:443
```

##### Step 2

Copy the below sh script for Linux or bat script for Windows


**Linux**
```
#!/bin/bash

input_file="input.txt"
output_file="output.txt"
wordlist="/path/to/wordlist.txt"  # Update this to the path of your wordlist

# Clear the output file if it already exists
> "$output_file"

while IFS= read -r line; do
  ip_port=(${line//:/ })
  ip=${ip_port[0]}
  port=${ip_port[1]}

  echo "Running Gobuster for $ip:$port..."

  gobuster dir -u http://$ip:$port -w $wordlist >> "$output_file" 2>&1
  echo -e "\n" >> "$output_file"  # Add a newline to separate results
done < "$input_file"

echo "Gobuster scan completed. Results saved in $output_file."
```

**Make the shell script executable** 
```
chmod +x run_gobuster.sh
```

**Run**
```
./run_gobuster.sh
```

**Windows**
```
@echo off
setlocal enabledelayedexpansion

set "input_file=input.txt"
set "output_file=output.txt"
set "wordlist=C:\path\to\wordlist.txt"  :: Update this to the path of your wordlist

:: Clear the output file if it already exists
echo. > "%output_file%"

for /f "tokens=1,2 delims=:" %%A in (%input_file%) do (
    set "ip=%%A"
    set "port=%%B"

    echo Running Gobuster for !ip!:!port!...

    gobuster dir -u http://!ip!:!port! -w %wordlist% >> "%output_file%" 2>&1
    echo. >> "%output_file%"  :: Add a newline to separate results
)

echo Gobuster scan completed. Results saved in %output_file%.
```

**Run**
```
run_gobuster.bat
```