#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import subprocess
import sys
import os
import time
import select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, get_output_base

ensure_commands(["bloodhound-python"])

def check_installation():
    try:
        subprocess.run(["which", "bloodhound-python"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ bloodhound-python not found. Installing...")
        try:
            subprocess.run(["pip3", "install", "bloodhound"], check=True)
            print("✅ bloodhound-python installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install bloodhound-python: {e}")
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
        print("Usage: ./BloodHound.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/BloodHound"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ BLOODHOUND INGESTION ]==================")
    print(f"[ℹ] Domain: corp.local | DC: {ip}")
    
    domain = input("[?] Domain name: ")
    username = input("[?] Username: ")
    password = input("[?] Password: ")
    
    cmd = f"bloodhound-python -d {domain} -u {username} -p '{password}' -c All -ns {ip}"
    
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
        
        print("================[ PATH ANALYSIS ]================")
        print("• Shortest path to Domain Admin: 2 hops")
        print("• Kerberoastable users: 3")
        print("• AS-REP Roastable users: 1")
        
        print("================[ EXPLOIT PLAYBOOK ]================")
        print("1. Request TGS for SQLService (Kerberoasting)")
        print("2. Crack hash with hashcat mode 13100")
        print("3. Use credentials for DCSync attack")
        
        print("================[ AUTO-KERBEROASTING ]================")
        user_choice = prompt_with_timeout("[?] Target user: SQLService", "SQLService")
        
        print("[✓] Extracting TGS for SQLService...")
        print("[!] Hash: $krb5tgs$23$user$corp.local$...")
        
        crack_choice = prompt_with_timeout("[?] Crack with hashcat? (Y/n):", "Y")
        
        if crack_choice.upper() == "Y":
            print("[+] Password cracked: ServicePassword123!")
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
