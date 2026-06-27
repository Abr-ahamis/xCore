#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import sys
import subprocess
import socket
import ftplib
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, get_output_base

ensure_commands(["nmap"])

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"{CYAN}================ FTP Anonymous Check ================{RESET}")

def check_ftp_anonymous(target_ip, port=21):
    """Check for FTP anonymous login"""
    print(f"{YELLOW}[~] Checking FTP anonymous access on {target_ip}:{port}...{RESET}")
    
    try:
        # Try to connect and login anonymously
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port, timeout=10)
        
        # Try anonymous login
        try:
            ftp.login('anonymous', 'anonymous@example.com')
            print(f"{GREEN}[✓] Anonymous FTP login successful!{RESET}")
            
            # Try to list directories
            try:
                files = []
                ftp.retrlines('LIST', files.append)
                
                print(f"{GREEN}[+] Directory listing:{RESET}")
                for file_info in files[:10]:  # Show first 10 entries
                    print(f"{CYAN}    {file_info}{RESET}")
                
                # Try to get current directory
                try:
                    current_dir = ftp.pwd()
                    print(f"{GREEN}[+] Current directory: {current_dir}{RESET}")
                except:
                    pass
                
                ftp.quit()
                return True, files
                
            except Exception as e:
                print(f"{YELLOW}[!] Could not list directory: {e}{RESET}")
                ftp.quit()
                return True, []
                
        except ftplib.error_perm as e:
            print(f"{RED}[!] Anonymous login failed: {e}{RESET}")
            ftp.quit()
            return False, []
            
    except socket.timeout:
        print(f"{RED}[!] Connection timeout to {target_ip}:{port}{RESET}")
        return False, []
    except ConnectionRefusedError:
        print(f"{RED}[!] Connection refused to {target_ip}:{port}{RESET}")
        return False, []
    except Exception as e:
        print(f"{RED}[!] FTP connection error: {e}{RESET}")
        return False, []

def run_nmap_ftp_anon(target_ip, port=21):
    """Use nmap FTP anonymous script as fallback"""
    print(f"{YELLOW}[~] Running nmap FTP anonymous check...{RESET}")
    
    try:
        result = subprocess.run([
            "nmap", "-p", str(port), "--script", "ftp-anon", target_ip
        ], capture_output=True, text=True, timeout=60)
        
        if "Anonymous FTP login allowed" in result.stdout:
            print(f"{GREEN}[✓] Nmap confirms anonymous FTP access{RESET}")
            return True, result.stdout
        else:
            print(f"{RED}[!] Nmap: Anonymous FTP not allowed{RESET}")
            return False, result.stdout
            
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Nmap FTP check timed out{RESET}")
        return False, ""
    except FileNotFoundError:
        print(f"{YELLOW}[!] Nmap not found, skipping script check{RESET}")
        return False, ""
    except Exception as e:
        print(f"{RED}[!] Nmap FTP check error: {e}{RESET}")
        return False, ""

def check_ftp_bounce(target_ip, port=21):
    """Check for FTP bounce attack vulnerability"""
    print(f"{YELLOW}[~] Checking for FTP bounce vulnerability...{RESET}")
    
    try:
        result = subprocess.run([
            "nmap", "-p", str(port), "--script", "ftp-bounce", target_ip
        ], capture_output=True, text=True, timeout=60)
        
        if "bounce working" in result.stdout.lower():
            print(f"{RED}[!] FTP bounce attack possible!{RESET}")
            return True, result.stdout
        else:
            print(f"{GREEN}[+] FTP bounce attack not possible{RESET}")
            return False, result.stdout
            
    except:
        return False, ""

def save_results(target_ip, port, anon_success, files, nmap_output, output_dir):
    """Save FTP check results to file"""
    output_file = output_dir / f"ftp_anon_check_{target_ip}_{port}.txt"
    
    with open(output_file, 'w') as f:
        f.write(f"FTP Anonymous Check Results\n")
        f.write(f"Target: {target_ip}:{port}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Anonymous Access: {'YES' if anon_success else 'NO'}\n\n")
        
        if files:
            f.write("Directory Listing:\n")
            for file_info in files:
                f.write(f"  {file_info}\n")
            f.write("\n")
        
        if nmap_output:
            f.write("Nmap Output:\n")
            f.write(nmap_output)
            f.write("\n")
    
    return output_file

def main():
    if len(sys.argv) < 2:
        print(f"{RED}Usage: {sys.argv[0]} <target_ip> [port]{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} 192.168.1.100{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} 192.168.1.100 21{RESET}")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    
    banner()
    print(f"{GREEN}[+] Target: {target_ip}:{port}{RESET}")
    print(f"{GREEN}[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{CYAN}{'='*50}{RESET}")
    
    # Create output directory
    output_dir = Path(get_output_base()) / "ftp_checks"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check FTP anonymous access
    anon_success, files = check_ftp_anonymous(target_ip, port)
    
    # Run nmap check as additional verification
    nmap_success, nmap_output = run_nmap_ftp_anon(target_ip, port)
    
    # Check for FTP bounce vulnerability
    bounce_vuln, bounce_output = check_ftp_bounce(target_ip, port)
    
    # Summary
    print(f"\n{CYAN}{'='*50}{RESET}")
    print(f"{BOLD}SUMMARY:{RESET}")
    
    if anon_success:
        print(f"{GREEN}[✓] Anonymous FTP access: ALLOWED{RESET}")
        if files:
            print(f"{GREEN}[+] Found {len(files)} directory entries{RESET}")
    else:
        print(f"{RED}[!] Anonymous FTP access: DENIED{RESET}")
    
    if nmap_success:
        print(f"{GREEN}[✓] Nmap confirmation: Anonymous access allowed{RESET}")
    
    if bounce_vuln:
        print(f"{RED}[!] FTP bounce vulnerability: DETECTED{RESET}")
    else:
        print(f"{GREEN}[+] FTP bounce vulnerability: Not detected{RESET}")
    
    # Save results
    output_file = save_results(target_ip, port, anon_success, files, 
                              f"{nmap_output}\n{bounce_output}", output_dir)
    
    print(f"\n{CYAN}{'='*50}{RESET}")
    print(f"{GREEN}[!] FTP check completed. Results saved to {output_file}{RESET}")
    
    # Return appropriate exit code
    if anon_success or bounce_vuln:
        print(f"{YELLOW}[!] Vulnerabilities found - manual investigation recommended{RESET}")
        sys.exit(0)  # Success - vulnerabilities found
    else:
        print(f"{GREEN}[+] No FTP vulnerabilities detected{RESET}")
        sys.exit(0)  # Success - no vulnerabilities

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] FTP check interrupted by user{RESET}")
        sys.exit(1)
