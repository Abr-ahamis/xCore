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

ensure_commands(["ldapsearch"])

def check_installation():
    try:
        subprocess.run(["which", "ldapsearch"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ ldapsearch not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "ldap-utils"], check=True)
            print("✅ ldapsearch installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install ldapsearch: {e}")
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
        print("Usage: ./ldapsearch.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/ldapsearch"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("================[ LDAP ENUMERATION MENU ]================")
    print("[1] Anonymous Query (3s default)")
    print("[2] Authenticated Query")
    print("[3] Custom Query")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    if choice == "1":
        base = prompt_with_timeout("[?] Search base [dc=example,dc=com]:", "dc=example,dc=com")
        print(f"[!] Proceeding with anonymous enumeration...")
        cmd = f"ldapsearch -x -H ldap://{ip}:{port} -b \"{base}\""
    elif choice == "2":
        username = input("[?] Username: ")
        password = input("[?] Password: ")
        base = prompt_with_timeout("[?] Search base [dc=example,dc=com]:", "dc=example,dc=com")
        cmd = f"ldapsearch -x -H ldap://{ip}:{port} -D \"{username}\" -w \"{password}\" -b \"{base}\""
    else:
        cmd = input("[?] Enter custom ldapsearch command: ")
    
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
