| Purpose                                       | Syntax                                                |
|-----------------------------------------------|-------------------------------------------------------|
| Directory brute-force attack                  | `gobuster dir -u https://example.com -w wordlist.txt` |
| Force-disable wildcard responses              | `gobuster dir -u https://example.com -w wordlist.txt -z` |
| Perform subdomain brute-forcing               | `gobuster dns -d example.com -w subdomains.txt`       |
| Set the number of concurrent threads         | `gobuster dir -u https://example.com -w wordlist.txt -t 50` |
| Exclude status codes from the output          | `gobuster dir -u https://example.com -w wordlist.txt -s 404,500` |
| Use specific HTTP methods for requests        | `gobuster dir -u https://example.com -w wordlist.txt -x .php,.html -m GET,POST` |

## Using gobuster with nmap results

### Step 1

Extract the IP list from `full_scan_results.gnmap`: 

```
Host: 192.168.0.1 ()	Ports: 80/open/tcp//http//TLB/, 443/open/tcp//ssl|https//TLB/	Ignored State: filtered (65533)
```

Reformat it into `input.txt`:

```
192.168.0.1:80
192.168.0.1:443
```

You can use my [nmap_results_plain_list.py](https://github.com/ashtonhogan/hack-the-planet/blob/main/Tools/nmap_results_plain_list.py) tool to automate this.

### Step 2

Run the below python script

```
import subprocess

input_file = "input.txt"
output_file = "output.txt"
wordlist = "wordlist.txt"

# Clear the output file if it already exists
with open(output_file, "w"):
    pass

with open(input_file, "r") as f:
    for line in f:
        ip, port = line.strip().split(":")
        print(f"Running Gobuster for {ip}:{port}...")

        with open(wordlist, "r") as wordlist_file:
            for word in wordlist_file:
                word = word.strip()
                
                # Replace hyphens and "con" to prevent gobuster entering directory enumeration mode
                if word == "-":
                    modified_word = "/-"
                elif word == "con":
                    modified_word = "/con"
                else:
                    modified_word = word
                
                # Print out the command issued to gobuster
                # print(f"gobuster dir -u http://{ip}:{port}/ -w {modified_word} -e -r -k -o {output_file}")
                
                subprocess.run([
                    "gobuster",
                    "dir",
                    "-u", f"http://{ip}:{port}/",
                    "-w", modified_word,
                    "-e", "-r", "-k",
                    "-o", output_file
                ])

print("Gobuster scan completed. Results saved in", output_file)
```
