#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import subprocess
import os
from pathlib import Path

from recon_deps import ensure_commands

# Colors
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Parse arguments
if len(sys.argv) < 3:
    print(f"{RED}Usage: ./curl_web_checker.py <target_ip> <comma_separated_ports>{RESET}")
    sys.exit(1)

ensure_commands(["curl", "python3"])

target_ip = sys.argv[1]
ports_raw = sys.argv[2]

try:
    ports = sorted(set(int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit()))
except ValueError:
    print(f"{RED}Invalid port list: {ports_raw}{RESET}")
    sys.exit(1)

# print(f"\n{CYAN}{BOLD}## curl_web_checker.py{RESET}")
# print(f"{YELLOW}This script checks passed ports for web server responses on {target_ip}.{RESET}\n")

print(f"{BOLD}{CYAN}{'='*20} Check Web Servers {'='*30}{RESET}")

found_web_server = False
results = []

for port in ports:
#    print(f"{YELLOW}[~] Checking port {port} on {target_ip}...{RESET}")
    try:
        result = subprocess.run(
            ["curl", "-s", "-I", "--max-time", "2", f"http://{target_ip}:{port}"],
            capture_output=True, text=True, timeout=3
        )
        status_line = result.stdout.splitlines()[0] if result.stdout else ""
        if "HTTP/" in status_line:
            results.append(f"{GREEN}✔ Found:{RESET}  port {BOLD}{port}{RESET} {CYAN}{status_line.strip()}{RESET}")
            found_web_server = True
    except subprocess.TimeoutExpired:
        continue

# print(f"{CYAN}{'='*60}{RESET}")

if found_web_server:
    print(f"{BOLD}{GREEN}[+] Web servers detected:{RESET}\n")
    for entry in results:
        print(entry)
#    print(f"\n{YELLOW}**[auto] Continuing to next, [ctrl + D] to stop...**{RESET}")

    # Run ffuf.py with web-hosting ports
# Get the path of this script's directory
script_dir = Path(__file__).resolve().parent
ffuf_script = script_dir / "ffuf.py"

web_ports = ",".join(str(port) for port in ports)

if ffuf_script.exists():
#    print(f"{GREEN}[✓] Running ffuf with detected web ports...{RESET}")
    subprocess.call(["python3", str(ffuf_script), target_ip, web_ports, "both"])
else:
    print(f"{RED}[!] ffuf.py not found at {ffuf_script}. Skipping FFUF phase.{RESET}")
