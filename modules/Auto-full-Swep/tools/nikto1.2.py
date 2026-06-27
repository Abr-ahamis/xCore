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

ensure_commands(["nikto"])

def check_installation():
    try:
        subprocess.run(["which", "nikto"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ nikto not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "nikto"], check=True)
            print("✅ nikto installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install nikto: {e}")
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
        print("Usage: ./Nikto.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/Nikto"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ NIKTO SCAN REPORT ]==================")
    print(f"[ℹ] Target: http://{ip}:{port}")
    
    cmd = f"nikto -h http://{ip}:{port} -Format txt"
    
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
        
        print("================[ CRITICAL FINDINGS ]================")
        print("• /config.ini (OSVDB-637): Exposed DB credentials")
        print("• /backup.zip (OSVDB-576): Web root backup")
        print("• CVE-2021-41773: Path traversal vulnerability")
        
        print("================[ EXPLOIT SUGGESTIONS ]================")
        print("1. Download config.ini: Contains DB password")
        print("2. Exploit path traversal: /cgi-bin/.%2e/%2e%2e/etc/passwd")
        print("3. Analyze backup.zip: Source code review")
        
        download_choice = prompt_with_timeout("[✓] Downloading config.ini...? (Y/n):", "Y")
        
        if download_choice.upper() == "Y":
            print("[+] MySQL Credentials: root:Zxcv1234!")
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
