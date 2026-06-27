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

ensure_commands(["rpcclient"])

def check_installation():
    try:
        subprocess.run(["which", "rpcclient"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ rpcclient not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "samba-common-bin"], check=True)
            print("✅ rpcclient installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install rpcclient: {e}")
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
        print("Usage: ./rpcclient.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/rpcclient"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ RPC ENUMERATION ]==================")
    print("1) Null Session (Anonymous login) [defualt 3sec]")
    print("2) Authenticated Session")
    print("=======================================================")
    
    choice = prompt_with_timeout("[?] Select?", "1")
    
    if choice == "1":
        print("=======================================================")
        print(f"[ℹ] Target: {ip} | Port: {port}")
        print(f"[✓] Running: rpcclient -U \"\" -N {ip}")
        cmd = f"rpcclient -U \"\" -N {ip}"
    else:
        print("=======================================================")
        username = input("[!] user: ")
        password = input("[!] pass: ")
        print("=======================================================")
        print(f"[ℹ] Target: {ip} | Port: {port}")
        print(f"[✓] Running: rpcclient -U \"{username}%{password}\" {ip}")
        cmd = f"rpcclient -U \"{username}%{password}\" {ip}"
    
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
