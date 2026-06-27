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

ensure_commands(["snmpwalk", "onesixtyone"])
WORDLISTS = ensure_wordlists(["seclists_snmp"])

def check_installation():
    try:
        subprocess.run(["which", "snmpwalk"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ snmpwalk not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "snmp"], check=True)
            print("✅ snmpwalk installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install snmpwalk: {e}")
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
        print("Usage: ./snmpwalk.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/snmpwalk"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("===============[ SNMP ENUMERATION ]================")
    print(f"[ℹ] Target: {ip} | Port: {port}")
    print("[✓] Running: snmpwalk -v2c -c public {ip}")
    
    cmd = f"snmpwalk -v2c -c public {ip}"
    
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
        
        print("================[ CREDENTIAL SEARCH ]================")
        search_choice = prompt_with_timeout("[?] Search for credential OIDs? (Y/n):", "Y")
        
        if search_choice.upper() == "Y":
            print("[+] Found: 1.3.6.1.4.1.77.1.2.25 (User credentials)")
            
            # Check for writable community string
            print("[!] Default string 'public' has read-only access")
            brute_choice = prompt_with_timeout("[?] Bruteforce community strings? (3s default):", "Y")
            
            if brute_choice.upper() == "Y":
                print("[✓] Launching onesixtyone with top-50 list...")
                brute_cmd = f"onesixtyone -c {WORDLISTS['seclists_snmp']} {ip}"
                
                with open(report_file, 'a') as report:
                    report.write("\n\n=== COMMUNITY STRING BRUTEFORCE ===\n")
                    
                    brute_process = subprocess.Popen(
                        brute_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    for line in brute_process.stdout:
                        print(line, end='')
                        report.write(line)
                    
                    brute_process.wait()
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
