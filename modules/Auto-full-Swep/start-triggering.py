#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import time
import re
import subprocess
import socket
import ftplib
import shutil
from pathlib import Path

from recon_deps import ensure_commands, get_hint_ports, get_output_base

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Configuration - using paths relative to script location
TRIGGER_FILE = os.path.join(SCRIPT_DIR, 'Wordlists', 'trigger.txt')
TOOLS_DIR = os.path.join(SCRIPT_DIR, 'tools')
RUSTSCAN_DEFAULT = './rustscan.txt'

ensure_commands(["python3", "nmap", "rustscan"])

# Default credentials for various services
DEFAULT_CREDENTIALS = {
    'ssh': [
        ('root', 'root'),
        ('admin', 'admin'),
        ('admin', 'password'),
        ('user', 'user'),
        ('guest', 'guest')
    ],
    'mysql': [
        ('root', ''),
        ('root', 'root'),
        ('admin', 'admin'),
        ('mysql', 'mysql')
    ]
}

def get_target_dir(target_ip):
    """Create and return the target directory path"""
    target_dir = f"{get_output_base()}/{target_ip}"
    os.makedirs(target_dir, exist_ok=True)
    return target_dir

def get_output_file(target_ip, filename):
    """Get the path to an output file in the target directory"""
    target_dir = get_target_dir(target_ip)
    return os.path.join(target_dir, filename)

def log_output(target_ip, filename, content):
    """Log content to a file in the target directory"""
    output_file = get_output_file(target_ip, filename)
    with open(output_file, 'a') as f:
        f.write(content + "\n")

def is_ip_or_host(target):
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False

def check_and_run_rustscan(target):
    target_dir = get_target_dir(target)
    scan_file = os.path.join(target_dir, "rustscan.txt")
    if os.path.exists(scan_file) and os.path.getsize(scan_file) > 0:
        print(f"{GREEN}[✓] Using existing rustscan results: {scan_file}{RESET}")
        return scan_file
    print(f"{YELLOW}[~] Running rustscan on {target}...{RESET}")
    try:
        hint_ports = get_hint_ports()
        if shutil.which("rustscan"):
            cmd = ["rustscan", "-a", target, "--ulimit", "5000", "-b", "500", "-t", "2000", "--", "-A"]
        else:
            if hint_ports:
                cmd = ["nmap", "-sT", "-sV", "--version-light", "-n", "-Pn", "--open", "-T4", "--max-retries", "0", "--host-timeout", "45s", f"-p{hint_ports}", target]
            else:
                cmd = ["nmap", "-Pn", "-sV", "-O", "-T4", "--open", "-p-", target]
        with open(scan_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=600, text=True)
        if result.returncode == 0:
            print(f"{GREEN}[✓] Rustscan completed: {scan_file}{RESET}")
            return scan_file
        else:
            print(f"{RED}[!] Rustscan failed with return code {result.returncode}{RESET}")
            if result.stderr:
                print(f"{RED}[!] Error: {result.stderr}{RESET}")
                log_output(target, "rustscan_error.log", result.stderr)
            return None
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Rustscan scan failed: {e}{RESET}")
        log_output(target, "rustscan_error.log", str(e))
        return None
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Rustscan scan timed out.{RESET}")
        log_output(target, "rustscan_error.log", "Rustscan scan timed out")
        return None
    except FileNotFoundError:
        print(f"{RED}[!] Rustscan not found. Please install rustscan.{RESET}")
        log_output(target, "rustscan_error.log", "Rustscan not found")
        return None

def run_nmap_scan(target):
    return check_and_run_rustscan(target)

def load_triggering_rules(filepath):
    rules = {}
    # Use the TRIGGER_FILE path defined in configuration
    trigger_path = TRIGGER_FILE
    if not os.path.isfile(trigger_path):
        print(f"{RED}[!] Trigger file not found: {trigger_path}{RESET}")
        return rules
    try:
        with open(trigger_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 3:
                        keyword = parts[0].strip().lower()
                        tool_name = parts[1].strip()
                        tool_script = parts[2].strip()
                        if tool_script:
                            rules[keyword] = {'tool_name': tool_name, 'script': tool_script}
                    elif len(parts) == 2:
                        keyword = parts[0].strip().lower()
                        tool_script = parts[1].strip()
                        if tool_script:
                            rules[keyword] = {'tool_name': keyword, 'script': tool_script}
    except Exception as e:
        print(f"{RED}[!] Error reading trigger file: {e}{RESET}")
    return rules

def read_scan_output(filepath):
    if not os.path.isfile(filepath):
        print(f"{YELLOW}[!] Scan output not found: {filepath}{RESET}")
        return ""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            return content
    except Exception as e:
        print(f"{RED}[!] Error reading scan file: {e}{RESET}")
        return ""

def extract_ports_and_services(scan_content):
    ports_services = {}
    service_ports = {}
    lines = scan_content.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        port_match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', line, re.IGNORECASE)
        if port_match:
            port, service = port_match.groups()
            ports_services[service.lower()] = port
            service_ports[port] = service.lower()
        for keyword in ['wordpress', 'mysql', 'apache']:
            if keyword in line:
                for j in range(i - 1, -1, -1):
                    prev_line = lines[j].strip()
                    port_match = re.search(r'(\d+)/tcp\s+open', prev_line, re.IGNORECASE)
                    if port_match:
                        port = port_match.group(1)
                        ports_services[keyword] = port
                        service_ports[port] = keyword
                        break
    return ports_services

def re_run_rustscan_fallback(target):
    print(f"{YELLOW}[!] Running fallback rustscan for {target}...{RESET}")
    try:
        if '/' in target:
            target_ip = os.path.basename(target).replace('rustscan.txt', '').replace('_', '.')
        else:
            target_ip = target
        target_dir = get_target_dir(target_ip)
        rustscan_script = os.path.join(SCRIPT_DIR, "rustscan.py")
        if os.path.exists(rustscan_script):
            result = subprocess.run(["python3", rustscan_script, target_ip],
                                    capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(f"{GREEN}[✓] Fallback rustscan completed{RESET}")
                output_file = os.path.join(target_dir, "rustscan.txt")
                if os.path.exists(output_file):
                    return read_scan_output(output_file)
            else:
                print(f"{RED}[!] Fallback rustscan failed{RESET}")
                log_output(target_ip, "rustscan_error.log", result.stderr)
        else:
            print(f"{RED}[!] Rustscan script not found at {rustscan_script}{RESET}")
            log_output(target_ip, "rustscan_error.log", f"Rustscan script not found at {rustscan_script}")
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Fallback rustscan timed out{RESET}")
        log_output(target_ip, "rustscan_error.log", "Fallback rustscan timed out")
    except Exception as e:
        print(f"{RED}[!] Fallback rustscan error: {e}{RESET}")
        log_output(target_ip, "rustscan_error.log", str(e))
    return ""

def run_tool(tool_info, target_ip, port=None):
    script_name = tool_info['script']
    tool_name = tool_info['tool_name']
    # Use the TOOLS_DIR path defined in configuration
    tools_dir = TOOLS_DIR
    script_path = os.path.join(tools_dir, script_name)
    if not os.path.exists(script_path):
        print(f"{RED}[!] Tool script not found: {script_path}{RESET}")
        return False
    print(f"\n{CYAN}[→] Running {tool_name} ({script_name}){RESET}")
    
    # Create output directory for this tool
    target_dir = get_target_dir(target_ip)
    tool_output_dir = os.path.join(target_dir, f"{tool_name}_output")
    os.makedirs(tool_output_dir, exist_ok=True)
    
    try:
        os.chmod(script_path, 0o755)
        cmd = [f"./{script_name}", target_ip]
        if port:
            cmd.append(str(port))
        original_cwd = os.getcwd()
        os.chdir(tools_dir)
        
        # Create output file for this tool run
        output_file = os.path.join(tool_output_dir, f"{tool_name}_output.txt")
        with open(output_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=600)
        
        # Log stderr if it exists
        if result.stderr:
            stderr_file = os.path.join(tool_output_dir, f"{tool_name}_error.log")
            with open(stderr_file, 'w') as f:
                f.write(result.stderr)
        
        os.chdir(original_cwd)
        if result.returncode == 0:
            print(f"{GREEN}[✓] {tool_name} completed successfully{RESET}")
            log_output(target_ip, "tool_execution.log", f"{tool_name} completed successfully")
            return True
        else:
            print(f"{YELLOW}[!] {tool_name} completed with warnings{RESET}")
            log_output(target_ip, "tool_execution.log", f"{tool_name} completed with warnings")
            return True
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] {tool_name} timed out{RESET}")
        log_output(target_ip, "tool_execution.log", f"{tool_name} timed out")
        return False
    except Exception as e:
        print(f"{RED}[!] Error running {tool_name}: {e}{RESET}")
        log_output(target_ip, "tool_execution.log", f"Error running {tool_name}: {e}")
        return False
    finally:
        try:
            os.chdir(original_cwd)
        except:
            pass

def check_ftp_anonymous(target_ip, port=21):
    print(f"{CYAN}[~] Checking FTP anonymous login on {target_ip}:{port}...{RESET}")
    log_output(target_ip, "ftp_anonymous.log", f"Checking FTP anonymous login on {target_ip}:{port}")
    
    target_dir = get_target_dir(target_ip)
    ftp_dir = os.path.join(target_dir, 'ftp')
    os.makedirs(ftp_dir, exist_ok=True)
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port, timeout=10)
        ftp.login('anonymous', '')
        success_msg = f"Anonymous FTP login allowed on {target_ip}:{port}"
        print(f"{GREEN}[✓] {success_msg}{RESET}")
        log_output(target_ip, "ftp_anonymous.log", success_msg)
        
        # List files
        files = []
        ftp.retrlines('LIST', files.append)
        files_list = "\n".join(files)
        print(f"{CYAN}[+] Files available:{RESET}")
        print(f"{CYAN}{files_list}{RESET}")
        log_output(target_ip, "ftp_anonymous.log", f"Files available:\n{files_list}")
        
        # Get clean list of filenames
        filenames = []
        try:
            ftp.retrlines('NLST', filenames.append)
        except:
            # Fallback to parsing LIST output if NLST fails
            for line in files:
                parts = line.split()
                if parts:
                    filenames.append(parts[-1])
        
        # Download each file
        download_log = []
        for filename in filenames:
            if filename in ['.', '..']:
                continue
            try:
                local_path = os.path.join(ftp_dir, filename)
                print(f"{CYAN}[~] Downloading {filename} to {local_path}{RESET}")
                download_log.append(f"Downloading {filename} to {local_path}")
                with open(local_path, 'wb') as f:
                    ftp.retrbinary(f'RETR {filename}', f.write)
                success_msg = f"Downloaded {filename}"
                print(f"{GREEN}[✓] {success_msg}{RESET}")
                download_log.append(success_msg)
            except Exception as e:
                error_msg = f"Failed to download {filename}: {e}"
                print(f"{RED}[!] {error_msg}{RESET}")
                download_log.append(error_msg)
        
        log_output(target_ip, "ftp_anonymous.log", "\n".join(download_log))
        ftp.quit()
        return True
    except Exception as e:
        error_msg = f"FTP anonymous check failed: {e}"
        print(f"{RED}[!] {error_msg}{RESET}")
        log_output(target_ip, "ftp_anonymous.log", error_msg)
        return False

def check_ssh_default(target_ip, port=22):
    print(f"{CYAN}[~] Checking SSH default credentials on {target_ip}:{port}...{RESET}")
    log_output(target_ip, "ssh_default.log", f"Checking SSH default credentials on {target_ip}:{port}")
    
    credentials = DEFAULT_CREDENTIALS.get('ssh', [])
    target_dir = get_target_dir(target_ip)
    
    try:
        for username, password in credentials:
            try:
                # Using subprocess to use ssh command
                cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
                       "-o", "StrictHostKeyChecking=no", 
                       f"{username}@{target_ip}", "echo 'SSH Login Successful'"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if "SSH Login Successful" in result.stdout:
                    success_msg = f"SSH login successful with {username}:{password}"
                    print(f"{GREEN}[✓] {success_msg}{RESET}")
                    log_output(target_ip, "ssh_default.log", success_msg)
                    
                    # Run some commands
                    cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
                           "-o", "StrictHostKeyChecking=no", 
                           f"{username}@{target_ip}", "whoami; id"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    output = result.stdout.strip().split('\n')
                    if len(output) >= 2:
                        user_info = f"Current user: {output[0]}"
                        id_info = f"ID: {output[1]}"
                        print(f"{CYAN}[+] {user_info}{RESET}")
                        print(f"{CYAN}[+] {id_info}{RESET}")
                        log_output(target_ip, "ssh_default.log", f"{user_info}\n{id_info}")
                    
                    return True
                else:
                    log_output(target_ip, "ssh_default.log", f"Failed login with {username}:{password}")
            except Exception as e:
                error_msg = f"Error with {username}:{password}: {e}"
                log_output(target_ip, "ssh_default.log", error_msg)
                continue
        
        print(f"{YELLOW}[i] SSH default credentials not found.{RESET}")
        log_output(target_ip, "ssh_default.log", "SSH default credentials not found")
        return False
    except Exception as e:
        error_msg = f"SSH connection failed: {e}"
        print(f"{RED}[!] {error_msg}{RESET}")
        log_output(target_ip, "ssh_default.log", error_msg)
        return False

def check_mysql_default(target_ip, port=3306):
    print(f"{CYAN}[~] Checking MySQL default credentials on {target_ip}:{port}...{RESET}")
    log_output(target_ip, "mysql_default.log", f"Checking MySQL default credentials on {target_ip}:{port}")
    
    credentials = DEFAULT_CREDENTIALS.get('mysql', [])
    target_dir = get_target_dir(target_ip)
    
    try:
        for username, password in credentials:
            try:
                # Using subprocess to use mysql client
                cmd = ["mysql", "-h", target_ip, "-P", str(port), "-u", username, f"-p{password}", 
                       "-e", "SELECT 'MySQL Login Successful';"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if "MySQL Login Successful" in result.stdout:
                    success_msg = f"MySQL login successful with {username}:{password}"
                    print(f"{GREEN}[✓] {success_msg}{RESET}")
                    log_output(target_ip, "mysql_default.log", success_msg)
                    
                    # Run some commands
                    cmd = ["mysql", "-h", target_ip, "-P", str(port), "-u", username, f"-p{password}", 
                           "-e", "SHOW DATABASES;"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    print(f"{CYAN}[+] Databases:{RESET}")
                    db_list = "Databases:\n"
                    for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                        if line.strip():
                            print(f"{CYAN}  {line}{RESET}")
                            db_list += f"  {line}\n"
                    
                    log_output(target_ip, "mysql_default.log", db_list)
                    return True
                else:
                    log_output(target_ip, "mysql_default.log", f"Failed login with {username}:{password}")
            except Exception as e:
                error_msg = f"Error with {username}:{password}: {e}"
                log_output(target_ip, "mysql_default.log", error_msg)
                continue
        
        print(f"{YELLOW}[i] MySQL default credentials not found.{RESET}")
        log_output(target_ip, "mysql_default.log", "MySQL default credentials not found")
        return False
    except Exception as e:
        error_msg = f"MySQL connection failed: {e}"
        print(f"{RED}[!] {error_msg}{RESET}")
        log_output(target_ip, "mysql_default.log", error_msg)
        return False

def check_anonymous_services(found_services, ports_services, target_ip):
    # Define the service check functions and their default ports
    service_checks = {
        'ftp': (check_ftp_anonymous, 21),
        'ssh': (check_ssh_default, 22),
        'mysql': (check_mysql_default, 3306)
    }
    
    for service in found_services:
        if service in service_checks:
            check_func, default_port = service_checks[service]
            port = int(ports_services.get(service, default_port))
            check_func(target_ip, port)

def main():
    print(f"{BOLD}{CYAN}====================== SMART SERVICE TRIGGERING ========================{RESET}")
    if len(sys.argv) < 2:
        print(f"{RED}Usage: {sys.argv[0]} <target_ip_or_scan_file>{RESET}")
        sys.exit(1)
    
    arg = sys.argv[1]
    if os.path.isfile(arg):
        scan_file = arg
        if len(sys.argv) > 2:
            target_ip = sys.argv[2]
        else:
            if '/' in scan_file:
                target_parts = scan_file.split('/')
                for part in target_parts:
                    if '.' in part and not part.endswith('.txt'):
                        target_ip = part.replace('_', '.')
                        break
                else:
                    target_ip = "127.0.0.1"
            else:
                target_ip = "127.0.0.1"
    else:
        if is_ip_or_host(arg):
            target_ip = arg
            scan_file = run_nmap_scan(target_ip)
            if not scan_file:
                print(f"{RED}[!] Rustscan failed or not available. Exiting.{RESET}")
                sys.exit(1)
        else:
            print(f"{RED}[!] Argument is neither a valid file nor a resolvable IP/hostname.{RESET}")
            sys.exit(1)
    
    # Create target directory and log the start of the scan
    target_dir = get_target_dir(target_ip)
    log_output(target_ip, "scan.log", f"Starting scan for {target_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"{GREEN}[+] Target: {target_ip}{RESET}")
    print(f"{GREEN}[+] Reading scan data from: {scan_file}{RESET}")
    log_output(target_ip, "scan.log", f"Reading scan data from: {scan_file}")
    
    scan_data = read_scan_output(scan_file)
    if not scan_data.strip():
        print(f"{YELLOW}[!] Scan data is empty or missing. Attempting fallback...{RESET}")
        log_output(target_ip, "scan.log", "Scan data is empty or missing. Attempting fallback...")
        scan_data = re_run_rustscan_fallback(target_ip)
        if not scan_data.strip():
            print(f"{RED}[!] No scan data available. Cannot proceed with service triggering.{RESET}")
            log_output(target_ip, "scan.log", "No scan data available. Cannot proceed with service triggering.")
            sys.exit(1)
    
    rules = load_triggering_rules(TRIGGER_FILE)
    if not rules:
        print(f"{RED}[!] No triggering rules loaded. Exiting.{RESET}")
        log_output(target_ip, "scan.log", "No triggering rules loaded. Exiting.")
        sys.exit(1)
    
    ports_services = extract_ports_and_services(scan_data)
    print(f"{CYAN}[+] Detected services and ports: {ports_services}{RESET}")
    log_output(target_ip, "scan.log", f"Detected services and ports: {ports_services}")
    
    found_services = []
    for keyword in rules:
        if keyword in scan_data or keyword in ports_services:
            found_services.append(keyword)
    
    if not found_services:
        print(f"{YELLOW}[!] No known services found in scan data.{RESET}")
        print(f"{CYAN}[i] Available keywords: {', '.join(rules.keys())}{RESET}")
        log_output(target_ip, "scan.log", f"No known services found in scan data. Available keywords: {', '.join(rules.keys())}")
        sys.exit(0)
    
    print(f"{GREEN}[+] Found {len(found_services)} matching services{RESET}")
    log_output(target_ip, "scan.log", f"Found {len(found_services)} matching services: {', '.join(found_services)}")
    
    check_anonymous_services(found_services, ports_services, target_ip)
    
    used_services = set()
    while True:
        print(f"\n{BOLD}{CYAN}DETECTED SERVICES:{RESET}")
        print(f"{CYAN}{'='*50}{RESET}")
        for i, service in enumerate(found_services, 1):
            tool_info = rules[service]
            port = ports_services.get(service, 'unknown')
            status = "✓ USED" if service in used_services else "READY"
            color = YELLOW if service in used_services else GREEN
            print(f"{color}  {i}. {service.upper():<12} → {tool_info['tool_name']:<15} (Port: {port}) [{status}]{RESET}")
        print(f"{CYAN}  0) Exit and continue to vuln-scan{RESET}")
        print(f"{CYAN}  00) Exit{RESET}")
        print(f"{CYAN}{'='*50}{RESET}")
        try:
            choice = input(f"{YELLOW}[?] Select service to scan (0-{len(found_services)} or 00 to exit): {RESET}").strip()
            if choice == "0":
                print(f"{GREEN}[✓] Launching vuln-scan (nmap-vuln.py)...{RESET}")
                log_output(target_ip, "scan.log", "Launching vuln-scan (nmap-vuln.py)...")
                vuln_path = os.path.join(SCRIPT_DIR, "nmap-vuln.py")
                if os.path.exists(vuln_path):
                    os.execv(sys.executable, ["python3", vuln_path, target_ip])
                else:
                    print(f"{RED}[!] nmap-vuln.py not found in the same folder.{RESET}")
                    log_output(target_ip, "scan.log", "nmap-vuln.py not found in the same folder.")
                    os._exit(1)
            elif choice == "00":
                print(f"{GREEN}[✓] Exiting...{RESET}")
                log_output(target_ip, "scan.log", "Exiting...")
                os._exit(0)
            if not choice.isdigit():
                print(f"{RED}[!] Invalid input. Please enter a number.{RESET}")
                continue
            choice_num = int(choice)
            if choice_num < 1 or choice_num > len(found_services):
                print(f"{RED}[!] Invalid selection. Please choose between 1-{len(found_services)}, 0 or 00.{RESET}")
                continue
            service = found_services[choice_num-1]
            if service in used_services:
                print(f"{YELLOW}[!] Service {service} already scanned. Please select another.{RESET}")
                continue
            tool_info = rules[service]
            port = ports_services.get(service, None)
            success = run_tool(tool_info, target_ip, port)
            if success:
                used_services.add(service)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Interrupted by user. Exiting...{RESET}")
            log_output(target_ip, "scan.log", "Interrupted by user. Exiting...")
            os._exit(0)
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")
            log_output(target_ip, "scan.log", f"Error: {e}")

if __name__ == "__main__":
    main()
