#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import subprocess
import re
from pathlib import Path
from datetime import datetime

from recon_deps import ensure_commands, get_hint_ports, get_output_base

# Terminal colors
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"{BOLD}{CYAN}====================== NMAP VULNERABILITY SCANNING ============================={RESET}")

def get_target_input():
    print(f"{YELLOW}[?]{RESET} Enter target IP or domain: ", end="")
    return input().strip()

def get_ports_from_rustscan_output(target):
    """Get ports from existing rustscan output to avoid re-scanning"""
    rustscan_file = f"{get_output_base()}/{target.replace('/', '_')}/rustscan.txt"
    
    if os.path.exists(rustscan_file):
        print(f"{GREEN}[+]{RESET} Using existing rustscan results from: {rustscan_file}")
        try:
            with open(rustscan_file, 'r') as f:
                content = f.read()
                # Extract ports from rustscan output
                ports = re.findall(r"(\d+)/tcp", content)
                open_ports = sorted(set(ports))
                if open_ports:
                    print(f"{GREEN}[+]{RESET} Found ports from rustscan: {', '.join(open_ports)}")
                    return ",".join(open_ports)
        except Exception as e:
            print(f"{YELLOW}[!] Error reading rustscan file: {e}{RESET}")
    
    return None

def run_fast_port_scan(target):
    """Fast port discovery using nmap with optimized settings"""
    print(f"{CYAN}=========== Fast Port Discovery ====================================={RESET}")
    hinted_ports = get_hint_ports()
    if hinted_ports:
        print(f"{GREEN}[+]{RESET} Using hinted ports: {hinted_ports}")
        return hinted_ports
    try:
        fast_scan_cmd = [
            "nmap", "-sS", "-T4", "--top-ports", "1000",
            "-n", "-Pn", "--min-rate", "1000", target
        ]
        result = subprocess.run(fast_scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=60)
        ports = re.findall(r"(\d+)/tcp\s+open", result.stdout)
        open_ports = sorted(set(ports))
        print(f"{GREEN}[+]{RESET} Open Ports Found: {', '.join(open_ports)}")
        return ",".join(open_ports)
    except subprocess.TimeoutExpired:
        print(f"{RED}[-] Fast scan timed out{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[-] Fast scan error: {e}{RESET}")
        return None

def run_optimized_vuln_scan(target, ports):
    """Optimized vulnerability scan with faster settings"""
    print(f"{CYAN}================= Optimized Vulnerability Scan ==================================={RESET}")
    
    # Use vuln category to run all vulnerability scripts
    critical_scripts = ["vuln"]
    
    script_list = ",".join(critical_scripts)
    
    cmd = [
        "nmap",
        "-sV",                    # Version detection
        "--script", script_list,  # Vulnerability scripts category
        "-T4",                    # Aggressive timing
        "--script-timeout", "30s", # 30 second script timeout
        "--host-timeout", "5m",   # 5 minute host timeout
        "-p", ports,
        target
    ]
    
    print(f"{YELLOW}[!] Running vulnerability scan command: {' '.join(cmd)}{RESET}")
    
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        if result.returncode != 0:
            print(f"{RED}[!] Nmap exited with error code {result.returncode}{RESET}")
            print(f"{RED}[!] stderr: {result.stderr.strip()}{RESET}")
            return ""
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}[!] Vulnerability scan timed out, returning partial results{RESET}")
        return "Scan timed out - partial results may be available"
    except Exception as e:
        print(f"{RED}[!] Vulnerability scan error: {e}{RESET}")
        return f"Scan error: {e}"

def save_output(target, raw_output):
    """Save scan output to file"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = Path(get_output_base()) / target.replace('/', '_')
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / "nmap-vuln.txt"
    
    with open(file_path, "w") as f:
        f.write(f"Nmap Vulnerability Scan Results\n")
        f.write(f"Target: {target}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("=" * 50 + "\n\n")
        f.write(raw_output)
    
    return file_path

def filter_essential_output(nmap_text):
    """Filter and highlight critical findings"""
    lines = nmap_text.splitlines()
    filtered = []
    port_info_started = False
    
    # Critical vulnerability keywords
    critical_keywords = [
        "vulnerable", "cve-", "critical", "high", "ms17-010", "ms08-067", 
        "heartbleed", "shellshock", "eternal", "conficker"
    ]

    for line in lines:
        line_lower = line.lower()
        
        # Show open ports with services
        if re.match(r"^\d+/tcp\s+open", line):
            if not port_info_started:
                filtered.append(f"{BOLD}Open Ports & Services:{RESET}")
                filtered.append("-" * 25)
            port_info_started = True
            filtered.append(f"{GREEN}{line.strip()}{RESET}")

        # Show critical vulnerabilities
        elif any(keyword in line_lower for keyword in critical_keywords):
            if "vulnerable" in line_lower:
                filtered.append(f"{RED}[CRITICAL] {line.strip()}{RESET}")
            elif "cve-" in line_lower:
                cve_match = re.search(r'(CVE-\d{4}-\d+)', line, re.IGNORECASE)
                if cve_match:
                    filtered.append(f"{YELLOW}[CVE] {line.strip()}{RESET}")
            else:
                filtered.append(f"{CYAN}[INFO] {line.strip()}{RESET}")
        
        # Show script results that indicate vulnerabilities
        elif line.strip().startswith("|") and any(keyword in line_lower for keyword in ["vuln", "exploit", "attack"]):
            filtered.append(f"    {line.strip()}")

    return "\n".join(filtered)

def chain_to_searchsploit(target):
    """Chain to searchsploit.py for exploit search"""
    script_dir = os.path.dirname(os.path.realpath(__file__))
    searchsploit_script = os.path.join(script_dir, "searchsploit.py")
    nmap_output_file = f"{get_output_base()}/{target.replace('/', '_')}/nmap-vuln.txt"
    
    if os.path.isfile(searchsploit_script) and os.path.exists(nmap_output_file):
        print(f"{GREEN}[✓] Launching searchsploit with nmap results{RESET}")
        try:
            subprocess.run([sys.executable, searchsploit_script, nmap_output_file])
        except Exception as e:
            print(f"{RED}[!] Failed to run searchsploit.py: {e}{RESET}")
    else:
        if not os.path.isfile(searchsploit_script):
            print(f"{RED}[!] searchsploit.py not found in {script_dir}{RESET}")
        if not os.path.exists(nmap_output_file):
            print(f"{RED}[!] Nmap output file not found: {nmap_output_file}{RESET}")

def main():
    banner()
    ensure_commands(["nmap", "searchsploit", "python3"])
    
    # Get target from command line or user input
    target = sys.argv[1] if len(sys.argv) > 1 else get_target_input()
    print(f"{GREEN}[+]{RESET} Target: {target}")

    # Try to get ports from existing rustscan output first (faster)
    ports = get_ports_from_rustscan_output(target)
    
    # If no existing ports found, run fast port scan
    if not ports:
        print(f"{YELLOW}[!] No existing port data found, running fast port discovery...{RESET}")
        ports = run_fast_port_scan(target)
    
    if not ports:
        print(f"{RED}[!] No open ports found. Exiting vulnerability scan.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[+]{RESET} Scanning ports: {ports}")

    # Run optimized vulnerability scan
    raw_output = run_optimized_vuln_scan(target, ports)
    clean_output = filter_essential_output(raw_output)

    # Display results
    print(f"{BOLD}{CYAN}====================== VULNERABILITY REPORT =========================================={RESET}")
    if clean_output.strip():
        print(clean_output)
    else:
        print(f"{GREEN}[+] No critical vulnerabilities detected with fast scan{RESET}")
        print(f"{YELLOW}[i] Run a more comprehensive scan manually if needed{RESET}")
    print("=" * 80)

    # Save output
    saved_path = save_output(target, raw_output)
    print(f"{GREEN}[✓]{RESET} Full report saved to: {saved_path}")
    
    # Chain to searchsploit for exploit search
    chain_to_searchsploit(target)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan aborted by user.{RESET}")
        sys.exit(1)
