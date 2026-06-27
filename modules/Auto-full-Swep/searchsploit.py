#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import re
import sys
import subprocess

from recon_deps import ensure_commands, get_output_base

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Check if input file is provided
if len(sys.argv) != 2:
    print(f"{RED}Usage: {sys.argv[0]} <nmap_results.txt>{RESET}")
    sys.exit(1)

ensure_commands(["searchsploit"])

nmap_file = sys.argv[1]

# Create output directory
OUTPUT_DIR = f"{get_output_base()}/searchsploit_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"{CYAN}================ searchsploit ===================================={RESET}")
print(f"{GREEN}[*] Extracting services and versions from nmap scan...{RESET}")

# Extract services and versions from nmap file
services = []
pattern = re.compile(
    r'\d+/tcp.*open.*?([\w-]+(?:/(?:httpd|ssh|ftp|mysql|apache|wordpress|smb|rdp|jenkins|docker|redis|elasticsearch|mongodb|nginx|iis|tomcat|mssql|oracle|postgresql|snmp))?)\s+([0-9]+(?:\.[0-9]+)*)'
)

try:
    with open(nmap_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                service, version = match.groups()
                services.append(f"{service} {version}")
except FileNotFoundError:
    print(f"{RED}[!] File not found: {nmap_file}{RESET}")
    sys.exit(1)

if not services:
    print(f"{YELLOW}[!] No services found in nmap output{RESET}")
    sys.exit(0)

print(f"{CYAN}" + "\n".join(services) + f"{RESET}")
print(f"{CYAN}==================================================================={RESET}")

# Process each service
for service in services:
    if service.strip():
        search_term_match = re.match(r'(\w+).* ([0-9.]+)', service)
        if not search_term_match:
            continue
        search_term = f"{search_term_match.group(1)} {search_term_match.group(2)}"
        print(f"{GREEN}[+] Checking exploits for: {search_term}{RESET}")

        service_name = search_term.split()[0]
        output_file = os.path.join(OUTPUT_DIR, f"{service_name}_exploits.txt")

        # Run searchsploit
        with open(output_file, 'w') as out:
            subprocess.run(["searchsploit", search_term, "-w"], stdout=out, stderr=subprocess.DEVNULL)

        if os.path.getsize(output_file) > 0:
            print(f"{GREEN}[✓] Exploits found for {search_term}. Results saved to {output_file}{RESET}")
            with open(output_file) as f:
                print("".join(f.readlines()[:10]))
        else:
            print(f"{YELLOW}[!] No exploits found for {search_term}{RESET}")
            # Try broader search
            broader_match = re.match(r'(\w+) ([0-9]+)\.[0-9]+.*', search_term)
            if broader_match:
                broader_term = f"{broader_match.group(1)} {broader_match.group(2)}"
                print(f"{YELLOW}[!] Trying broader search: {broader_term}{RESET}")
                with open(output_file, 'w') as out:
                    subprocess.run(["searchsploit", broader_term, "-w"], stdout=out, stderr=subprocess.DEVNULL)

                if os.path.getsize(output_file) > 0:
                    print(f"{GREEN}[✓] Exploits found with broader search. Results saved to {output_file}{RESET}")
                    with open(output_file) as f:
                        print("".join(f.readlines()[:10]))
                else:
                    print(f"{YELLOW}[!] No exploits found with broader search{RESET}")

print(f"{CYAN}======================================================================{RESET}")
print(f"{GREEN}[!] Searchsploit scan completed. Results saved in {OUTPUT_DIR}{RESET}")
