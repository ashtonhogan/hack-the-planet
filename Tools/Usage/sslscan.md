| Purpose                                     | Syntax                                                   |
|---------------------------------------------|----------------------------------------------------------|
| Perform a basic SSL/TLS scan on a single host | `sslscan hostname.com`                                   |
| Perform a basic SSL/TLS scan on multiple hosts | `sslscan hostname1.com hostname2.com hostname3.com`      |
| Scan a specific port for SSL/TLS vulnerabilities | `sslscan --no-colour --no-failed hostname.com:443`       |
| Scan for SSL/TLS vulnerabilities and output in XML format | `sslscan --xml=scan_results.xml hostname.com`            |
| Scan for SSL/TLS vulnerabilities and output in JSON format | `sslscan --json=scan_results.json hostname.com`          |
| Scan for SSL/TLS vulnerabilities and output in CSV format | `sslscan --csv=scan_results.csv hostname.com`            |

## Using sslscan with nmap results

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

Run the below python script to collect all the certificates

```
import re
import subprocess
import os

# Define filenames
SCAN_RESULTS_FILE = 'input.txt'
OUTPUT_RESULTS_DIR = 'scan_results'

def run_sslscan(ip, port):
    """Run sslscan for a given IP:port and return stdout."""
    cmd = ['sslscan', '--verbose', '--no-color', f"{ip}:{port}"]
    print(f"Issuing command: {' '.join(cmd)}")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    if "ERROR: Could not resolve hostname" in stderr:
        print(stderr.strip())
    print(f"Command output:\n{stdout}")
    return stdout

def save_sslscan_output(ip, port, output):
    """Save sslscan output to a file."""
    filename = os.path.join(OUTPUT_RESULTS_DIR, f"{ip}-{port}.txt")
    with open(filename, 'w') as file:
        file.write(output)

def main():
    # Create the output directory if it doesn't exist
    os.makedirs(OUTPUT_RESULTS_DIR, exist_ok=True)
    
    with open(SCAN_RESULTS_FILE, 'r') as f:
        for line in f:
            ip, port = line.strip().split(':')
            sslscan_output = run_sslscan(ip, port)
            save_sslscan_output(ip, port, sslscan_output)

if __name__ == "__main__":
    main()
```

### Step 3

Run the below python script to check all the certificates

```

```

Here is a sample scan with a lot of vulnerabilities for testing purposes:

```
Version: 2.1.3 Windows 64-bit (Mingw)
OpenSSL 3.0.9 30 May 2023

Connected to 71.18.253.67

Some servers will fail to response to SSLv3 ciphers over STARTTLS
If your scan hangs, try using the --tlsall option

Testing SSL server 71.18.253.67 on port 443 using SNI name 71.18.253.67

  SSL/TLS Protocols:
SSLv2     enabled
SSLv3     enabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   enabled

  TLS Fallback SCSV:
OpenSSL OpenSSL 3.0.9 30 May 2023 looks like version 0.9.8m or later; I will try SSL_OP to enable renegotiation
OpenSSL OpenSSL 3.0.9 30 May 2023 looks like version 0.9.8m or later; I will try SSL_OP to enable renegotiation
Server supports TLS Fallback SCSV

  TLS renegotiation:
OpenSSL OpenSSL 3.0.9 30 May 2023 looks like version 0.9.8m or later; I will try SSL_OP to enable renegotiation
use_unsafe_renegotiation_op
Session renegotiation not supported

  TLS Compression:
OpenSSL OpenSSL 3.0.9 30 May 2023 looks like version 0.9.8m or later; I will try SSL_OP to enable renegotiation
Compression disabled

  Heartbleed:
TLSv1.0 vulnerable to heartbleed
TLSv1.1 vulnerable to heartbleed

  Supported Server Cipher(s):
SSL_connect() returned: 1
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
SSL_connect() returned: 1
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
SSL_connect() returned: 1
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
SSL_connect() returned: -1
SSL_get_current_cipher() returned NULL; this indicates that the server did not choose a cipher from our list (TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256)
SSL_connect() returned: 1
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-ARIA256-GCM-SHA384      Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-ARIA128-GCM-SHA256      Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CAMELLIA256-SHA384  Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-CAMELLIA128-SHA256  Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384            
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-CCM8                  
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-CCM                   
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ARIA256-GCM-SHA384           
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256            
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-CCM8                  
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-CCM                   
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ARIA128-GCM-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-SHA256                
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-SHA256                
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-SHA                   
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA              
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-SHA                   
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA              
SSL_connect() returned: -1
(ALL:COMPLEMENTOFALL:!ECDHE-RSA-AES256-GCM-SHA384:!ECDHE-RSA-CHACHA20-POLY1305:!ECDHE-ARIA256-GCM-SHA384:!ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-ARIA128-GCM-SHA256:!ECDHE-RSA-AES256-SHA384:!ECDHE-RSA-CAMELLIA256-SHA384:!ECDHE-RSA-AES128-SHA256:!ECDHE-RSA-CAMELLIA128-SHA256:!ECDHE-RSA-AES256-SHA:!ECDHE-RSA-AES128-SHA:!AES256-GCM-SHA384:!AES256-CCM8:!AES256-CCM:!ARIA256-GCM-SHA384:!AES128-GCM-SHA256:!AES128-CCM8:!AES128-CCM:!ARIA128-GCM-SHA256:!AES256-SHA256:!CAMELLIA256-SHA256:!AES128-SHA256:!CAMELLIA128-SHA256:!AES256-SHA:!CAMELLIA256-SHA:!AES128-SHA:!CAMELLIA128-SHA)


  Server Key Exchange Group(s):
TLSv1.3  128 bits  secp256r1 (NIST P-256)
TLSv1.3  192 bits  secp384r1 (NIST P-384)
TLSv1.3  128 bits  x25519
TLSv1.2  128 bits  secp256r1 (NIST P-256)
TLSv1.2  192 bits  secp384r1 (NIST P-384)
TLSv1.2  128 bits  x25519

  SSL Certificate:
Signature Algorithm: MD5withRSA
Signature Algorithm: MD5withRSAEncryption
Signature Algorithm: SHA1withRSA
Signature Algorithm: SHA1withRSAEncryption
Signature Algorithm: MD2withRSA
Signature Algorithm: MD2withRSAEncryption
Signature Algorithm: SHA224withRSA
Signature Algorithm: SHA224withRSAEncryption
Signature Algorithm: DSAwithSHA1
Signature Algorithm: RSAWithMD5
Signature Algorithm: ECDSAwithSHA1
Signature Algorithm: SHA256withRSA
Signature Algorithm: ECDSAwithSHA256
Signature Algorithm: ECDSAwithSHA384
Signature Algorithm: MD5withRSA1024
Signature Algorithm: SHA1withRSA1024
Signature Algorithm: SHA256withRSA1024
Signature Algorithm: ECDSAwithSHA256andSecp160r1
Signature Algorithm: ECDSAwithSHA384andSecp192r1
RSA Key Strength:    256

Subject:  example.com
Altnames: DNS:*.example.com, DNS:example.com
Issuer:   example.com

Not valid before: Apr 23 00:00:00 2020 GMT
Not valid after:  Apr 23 23:59:59 2021 GMT
```

### Vulnerabilities Explained:

**Weak Protocols Enabled**
```
TLSv1.0   enabled
TLSv1.1   enabled
```

**Heartbleed**
```
TLSv1.0 vulnerable to heartbleed
TLSv1.1 vulnerable to heartbleed
```

**Weak signature algorithm**
```
Signature Algorithm: MD5withRSA
Signature Algorithm: MD5withRSAEncryption
Signature Algorithm: SHA1withRSA
Signature Algorithm: SHA1withRSAEncryption
Signature Algorithm: MD2withRSA
Signature Algorithm: MD2withRSAEncryption
Signature Algorithm: SHA224withRSA
Signature Algorithm: SHA224withRSAEncryption
Signature Algorithm: DSAwithSHA1
Signature Algorithm: RSAWithMD5
Signature Algorithm: ECDSAwithSHA1
Signature Algorithm: SHA256withRSA
Signature Algorithm: ECDSAwithSHA256
Signature Algorithm: ECDSAwithSHA384
Signature Algorithm: MD5withRSA1024
Signature Algorithm: SHA1withRSA1024
Signature Algorithm: SHA256withRSA1024
Signature Algorithm: ECDSAwithSHA256andSecp160r1
Signature Algorithm: ECDSAwithSHA384andSecp192r1
RSA Key Strength:    256
```

**Expired SSL Certificate**
```
Not valid before: Apr 23 00:00:00 2020 GMT
Not valid after:  Apr 23 23:59:59 2021 GMT
```

**Weak Cipher Suites**
```
SSL_connect() returned: 1
Preferred TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
SSL_connect() returned: 1
Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
SSL_connect() returned: 1
Accepted  TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
SSL_connect() returned: -1
SSL_get_current_cipher() returned NULL; this indicates that the server did not choose a cipher from our list (TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256)
SSL_connect() returned: 1
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-ARIA256-GCM-SHA384      Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-ARIA128-GCM-SHA256      Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA384       Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-CAMELLIA256-SHA384  Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256       Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-CAMELLIA128-SHA256  Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384            
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-CCM8                  
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-CCM                   
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  ARIA256-GCM-SHA384           
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256            
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-CCM8                  
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-CCM                   
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  ARIA128-GCM-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-SHA256                
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-SHA256                
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA256           
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  AES256-SHA                   
SSL_connect() returned: 1
Accepted  TLSv1.2  256 bits  CAMELLIA256-SHA              
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  AES128-SHA                   
SSL_connect() returned: 1
Accepted  TLSv1.2  128 bits  CAMELLIA128-SHA              
SSL_connect() returned: -1
(ALL:COMPLEMENTOFALL:!ECDHE-RSA-AES256-GCM-SHA384:!ECDHE-RSA-CHACHA20-POLY1305:!ECDHE-ARIA256-GCM-SHA384:!ECDHE-RSA-AES128-GCM-SHA256:!ECDHE-ARIA128-GCM-SHA256:!ECDHE-RSA-AES256-SHA384:!ECDHE-RSA-CAMELLIA256-SHA384:!ECDHE-RSA-AES128-SHA256:!ECDHE-RSA-CAMELLIA128-SHA256:!ECDHE-RSA-AES256-SHA:!ECDHE-RSA-AES128-SHA:!AES256-GCM-SHA384:!AES256-CCM8:!AES256-CCM:!ARIA256-GCM-SHA384:!AES128-GCM-SHA256:!AES128-CCM8:!AES128-CCM:!ARIA128-GCM-SHA256:!AES256-SHA256:!CAMELLIA256-SHA256:!AES128-SHA256:!CAMELLIA128-SHA256:!AES256-SHA:!CAMELLIA256-SHA:!AES128-SHA:!CAMELLIA128-SHA)
```

**Self-Signed Certificate**
```
Subject:  example.com
Altnames: DNS:*.example.com, DNS:example.com
Issuer:   example.com
```

**SSL/TLS Misconfiguration**
```
??
```

**Certificate Issuance Issue**
```
??
```