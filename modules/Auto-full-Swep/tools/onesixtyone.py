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

ensure_commands(["onesixtyone"])
WORDLISTS = ensure_wordlists(["seclists_snmp"])

def check_installation():
    try:
        subprocess.run(["which", "onesixtyone"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ onesixtyone not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "onesixtyone"], check=True)
            print("✅ onesixtyone installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install onesixtyone: {e}")
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
        print("Usage: ./onesixtyone.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/onesixtyone"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("================[ SNMP BRUTEFORCE SCAN ]================")
    print("[1] Default 3sec")
    print("[2] multi-IP scan")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] select ?", "1")
    
    if choice == "1":
        wordlist_choice = prompt_with_timeout("[?] Defualt wordlist {Y/N}?", "Y")
        if wordlist_choice.upper() == "Y":
            cmd = f"onesixtyone -c {WORDLISTS['seclists_snmp']} {ip}"
        else:
            wordlist = input("[!] Enter wordlists path? ")
            cmd = f"onesixtyone -c {wordlist} {ip}"
    else:
        ip_file = input("[!] Enter the path ip file? ")
        wordlist_choice = prompt_with_timeout("[?] Defualt wordlist Y 3sec ? {Y/N}?", "Y")
        if wordlist_choice.upper() == "Y":
            cmd = f"onesixtyone -c {WORDLISTS['seclists_snmp']} -i {ip_file}"
        else:
            wordlist = input("[!] Enter wordlists path? ")
            cmd = f"onesixtyone -c {wordlist} -i {ip_file}"
    
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
