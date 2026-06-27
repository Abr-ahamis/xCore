#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import subprocess
from pathlib import Path

from recon_deps import ensure_commands, get_output_base

# ANSI color codes
RED = "\033[1;31m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Base directory: where this script is located
BASE_DIR = Path(__file__).resolve().parent

# Output directories
OUTPUT_DIR = "/tmp/VirexCore"
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")

def ensure_output_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
        test_file = Path(path) / ".write_test"
        test_file.write_text("", encoding="utf-8")
        test_file.unlink(missing_ok=True)
    except PermissionError:
        subprocess.run(["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", path], check=False)
        os.makedirs(path, exist_ok=True)

def banner():
    os.system("clear")
    print(f"{BLUE}╔═══════════════════[ ⚙ {BOLD}RUSTSCAN AUTOMATION{RESET}{BLUE} ]════════════════════╗")
    print(f"{CYAN}     📁 Output Directory: → {OUTPUT_DIR}{RESET}")
    print(f"{BLUE}╠════════════════════════════════════════════════════════════╣")
    print(f"{GREEN}     🚀 {BOLD}AUTOMATION FLOW:{RESET}")
    print(f"{YELLOW}     [ RECON ]")
    print(f"{YELLOW}        ➤ [ SERVICE ENUMERATION ]")
    print(f"{YELLOW}          ➤ [ WEB SERVER VERIFICATION ]")
    print(f"{YELLOW}            ➤ [ SMART SERVICE TRIGGERING ]")
    print(f"{YELLOW}              ➤ [ WEB DIRECTORY ENUMERATION ]")
    print(f"{YELLOW}                ➤ [ NMAP VULNERABILITY SCAN ]")
    print(f"{YELLOW}                  ➤ [ EXPLOIT SEARCH ]")
    print(f"{BLUE}╚════════════════════════════════════════════════════════════╝{RESET}")

def run_script(script_name, target):
    """Run a script located in the same directory"""
    script_path = os.path.join(BASE_DIR, script_name)

    if not os.path.exists(script_path):
        print(f"{RED}[!] Script not found: {script_path}{RESET}")
        return False

    try:
        cmd = ["python3", script_path, target]
        subprocess.run(cmd, check=True)
        print(f"{GREEN}[✓] {script_name} completed successfully{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] {script_name} failed: {e}{RESET}")
        return False
    except FileNotFoundError:
        print(f"{RED}[!] Could not find Python interpreter or script{RESET}")
        return False

def main():
    global OUTPUT_DIR, REPORTS_DIR
    OUTPUT_DIR = get_output_base(OUTPUT_DIR)
    REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
    banner()
    ensure_commands(["python3", "curl", "ffuf", "nmap", "searchsploit"])
    target = input(f"{CYAN}     🔍 Target IP or Domain : {RESET}").strip()

    if not target:
        print(f"{RED}[!] No target provided. Exiting...{RESET}")
        sys.exit(1)

    # Create output directories
    ensure_output_dir(OUTPUT_DIR)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    target_dir = os.path.join(OUTPUT_DIR, target.replace('/', '_'))
    os.makedirs(target_dir, exist_ok=True)

    # Set environment variables
    os.environ["TARGET"] = target
    os.environ["OUTPUT_DIR"] = OUTPUT_DIR

    # Run rustscan.py from the same directory
    if run_script("rustscan.py", target):
        sys.exit(0)
    else:
        print(f"{RED}[!] RustScan failed. Exiting...{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Scan cancelled by user.{RESET}")
        sys.exit(0)
