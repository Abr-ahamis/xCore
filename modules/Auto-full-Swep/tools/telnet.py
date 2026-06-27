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

ensure_commands(["telnet"])

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
        print("Usage: ./Telnet.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/Telnet"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    print("================[ TELNET MENU ]================")
    print("[1] Basic Connection (3s default)")
    print("[2] SMTP Testing")
    print("[3] HTTP Manual Test")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    if choice == "1":
        cmd = f"echo 'quit' | telnet {ip} {port}"
    elif choice == "2":
        cmd = f"echo -e 'EHLO test.com\\nVRFY root\\nquit' | telnet {ip} {port}"
    else:
        cmd = f"echo -e 'GET / HTTP/1.0\\n\\n' | telnet {ip} {port}"
    
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
