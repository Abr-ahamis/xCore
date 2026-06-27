#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import subprocess
import sys
import os
import time
import select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, ensure_wordlists, get_output_base

ensure_commands(["gobuster"])
WORDLISTS = ensure_wordlists(["seclists_web", "seclists_dns"])

def check_installation():
    try:
        subprocess.run(["which", "gobuster"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ gobuster not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "gobuster"], check=True)
            print("✅ gobuster installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install gobuster: {e}")
            return False

def prompt_with_timeout(prompt, default=None, timeout=3):
    print(prompt)
    print(f"⏱️ Timeout in {timeout} seconds (default: {default})")
    
    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        user_input = sys.stdin.readline().rstrip()
        return user_input if user_input else default
    else:
        print(f"⏱️ Timeout, using default: {default}")
        return default

def main():
    if len(sys.argv) != 3:
        print("Usage: ./Gobuster.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/Gobuster"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("================[ GOBUSTER MENU ]================")
    print("[1] Directory Scan (3s default)")
    print("[2] Subdomain Enum")
    print("[3] Vhost Discovery")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    wordlist_choice = prompt_with_timeout("[?] Wordlist: default (raft-medium)? Y", "Y")
    if wordlist_choice.upper() == "Y":
        wordlist = WORDLISTS["seclists_dns"] if choice == "2" else WORDLISTS["seclists_web"]
    else:
        wordlist = input("[!] Path: ")
    
    if choice == "1":
        cmd = f"gobuster dir -u http://{ip}:{port} -w {wordlist}"
    elif choice == "2":
        domain = input("[!] Domain: ")
        cmd = f"gobuster dns -d {domain} -w {wordlist}"
    else:
        cmd = f"gobuster vhost -u http://{ip}:{port} -w {wordlist}"
    
    try:
        with open(report_file, 'w') as report:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            for line in process.stdout:
                print(line, end='')
                report.write(line)
            
            process.wait()
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
