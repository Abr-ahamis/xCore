#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import re
import subprocess
import shutil
from pathlib import Path

from recon_deps import ensure_commands, get_hint_ports, get_output_base

# Colors
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Usage check
if len(sys.argv) != 2:
    print(f"{YELLOW}Usage: {sys.argv[0]} <target_ip>{RESET}")
    sys.exit(1)

ensure_commands(["python3", "nmap", "rustscan"])

target = sys.argv[1]
outdir = Path(get_output_base()) / target.replace('/', '_')
outdir.mkdir(exist_ok=True, parents=True)
outfile = outdir / "rustscan.txt"
stream_log = outdir / "scan.log"

# Header
print(f"{CYAN}{BOLD}======================[ Rustscan ]==================================={RESET}")
print(f"{GREEN}[+] Running Rustscan scan...  [+] Target: {target}{RESET}")

hint_ports = get_hint_ports()
if shutil.which("rustscan"):
    cmd = [
        "rustscan",
        "-a", target,
        "--ulimit", "5000",
        "-b", "500",
        "-t", "2000",
        "--",
        "-A",
        "-oN", str(outfile),
    ]
else:
    if hint_ports:
        cmd = ["nmap", "-sT", "-sV", "--version-light", "-n", "-Pn", "--open", "-T4", "--max-retries", "0", "--host-timeout", "45s", f"-p{hint_ports}", target, "-oN", str(outfile)]
    else:
        cmd = ["nmap", "-Pn", "-sV", "-O", "-T4", "--open", "-p-", target, "-oN", str(outfile)]

# Start Rustscan
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

open_ports = []
services_details = []
os_info = []

capture_service = False
service_block = []
seen_ports = set()

# Section: Port Summary
print(f"{YELLOW}=============[ OPEN PORTS ]=================={RESET}")

with stream_log.open("w", encoding="utf-8", errors="ignore") as report:
    for line in proc.stdout:
        report.write(line)
        report.flush()
        line = line.rstrip()

        if line.startswith("Open "):
            port_match = re.search(r":(\d+)\b", line)
            if port_match:
                port = port_match.group(1)
                if port not in seen_ports:
                    seen_ports.add(port)
                    open_ports.append(port)
                    print(f"{GREEN}{port}{RESET}")
            else:
                print(f"{GREEN}{line}{RESET}")

        elif re.match(r'^(\d+)/tcp\s+open\s+', line):
            port = re.match(r'^(\d+)/tcp\s+open', line).group(1)
            if port not in seen_ports:
                seen_ports.add(port)
                open_ports.append(port)
                print(f"{GREEN}{port}{RESET}")
            if service_block:
                services_details.append("\n".join(service_block))
                service_block = []
            service_block.append(line)
            capture_service = True

        elif capture_service and line.startswith("|"):
            service_block.append(line)

        elif capture_service and not line.startswith("|"):
            services_details.append("\n".join(service_block))
            service_block = []
            capture_service = False

        elif line.lower().startswith(("running:", "os cpe:", "os details:", "device type:", "service info:")):
            os_info.append(line)

# Append remaining service block
if service_block:
    services_details.append("\n".join(service_block))

proc.wait()

if outfile.exists():
    capture_service = False
    service_block = []
    with outfile.open("r", encoding="utf-8", errors="ignore") as nmap_report:
        for raw_line in nmap_report:
            line = raw_line.rstrip()
            if re.match(r'^(\d+)/tcp\s+open\s+', line):
                port = re.match(r'^(\d+)/tcp\s+open', line).group(1)
                if port not in seen_ports:
                    seen_ports.add(port)
                    open_ports.append(port)
                if service_block:
                    services_details.append("\n".join(service_block))
                    service_block = []
                service_block.append(line)
                capture_service = True
            elif capture_service and line.startswith("|"):
                service_block.append(line)
            elif capture_service and not line.startswith("|"):
                if service_block:
                    services_details.append("\n".join(service_block))
                service_block = []
                capture_service = False
            elif line.lower().startswith(("running:", "os cpe:", "os details:", "device type:", "service info:")):
                os_info.append(line)

# Deduplicate while preserving order
open_ports = list(dict.fromkeys(open_ports))
deduped_services = []
seen_blocks = set()
for block in services_details:
    if block not in seen_blocks:
        seen_blocks.add(block)
        deduped_services.append(block)
services_details = deduped_services
os_info = list(dict.fromkeys(os_info))

# Scan Complete
print(f"{CYAN}{'='*65}")
print(f"[+] Scan completed")
print(f"{'='*65}{RESET}")

# Port & Service Detection
print(f"{YELLOW}==============[ PORT & SERVICE DETECTION ]=================={RESET}")
for port in open_ports:
    print(f"{GREEN}{port}{RESET}")

# Detailed Service Info
if services_details:
    print(f"\n{YELLOW}--- Services (detailed) ---{RESET}")
    print("\n\n".join(services_details))

# OS Detection Info
if os_info:
    print(f"\n{YELLOW}========================[ OS Detection ]=============================={RESET}")
    print("\n".join(os_info))

# Full Report
print(f"{CYAN}{'='*91}")
print(f"{GREEN}Full report: {outfile}   {RESET}{BOLD}{{ without cuts }}{RESET}")
print(f"{CYAN}{'='*65}")

# Run curl_web_checker.py if available
script_dir = Path(__file__).parent
curl_script = script_dir / "curl_web_checker.py"

if curl_script.exists():
    if open_ports:
        port_args = ",".join(open_ports)
#        print(f"{GREEN}[✓] Start Curl for Web hosting ports...{RESET}")
        subprocess.call(["python3", str(curl_script), target, port_args])
    else:
        print(f"{YELLOW}[!] No open ports found to pass to curl_web_checker.py. Skipping...{RESET}")
else:
    print(f"{YELLOW}[!] curl_web_checker.py not found. Skipping...{RESET}")
