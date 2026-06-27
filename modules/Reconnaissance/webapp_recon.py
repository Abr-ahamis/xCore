#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import time
import subprocess
import re
import json
import threading
import signal
import shutil  # Added import
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Auto-full-Swep"))
from recon_deps import ensure_commands, ensure_wordlists, get_hint_ports, get_output_base

# Color definitions
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WebappRecon:
    def __init__(self, target):
        ensure_commands(["curl", "whatweb", "host", "subfinder", "ffuf", "nikto"])
        wordlists = ensure_wordlists(["seclists_web", "seclists_dns"])
        self.target = target
        self.output_base = get_output_base()
        self.output_dir = self._create_output_dir(target)
        self.open_ports = set()  # Using set to avoid duplicates
        self.web_ports = set()   # Using set to avoid duplicates
        self.ffuf_mode = "2"     # Default to path fuzzing
        self.wordlist = wordlists["seclists_web"]
        self.file_extensions = "php,bak,zip,html,txt,js,conf,json,old,swp"
        
        # Normalize URL
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"http://{self.target}"
        
        # Set Python cache prefix to target-specific directory
        sys.pycache_prefix = self.output_dir
        
        # Remove existing __pycache__ directories
        self._remove_pycache()
        
    def _create_output_dir(self, target):
        # Sanitize target for directory name
        safe_target = re.sub(r'[^\w\-_.]', '_', target)
        output_dir = os.path.join(self.output_base, safe_target)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def _remove_pycache(self):
        """Remove __pycache__ directories in the project folder"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        for root, dirs, files in os.walk(script_dir):
            if '__pycache__' in dirs:
                pycache_path = os.path.join(root, '__pycache__')
                try:
                    shutil.rmtree(pycache_path)
                    print(f"{Colors.YELLOW}[+] Removed {pycache_path}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Failed to remove {pycache_path}: {str(e)}{Colors.RESET}")
    
    def _handle_eof(self, signum, frame):
        """Handle Ctrl+D (EOF)"""
        print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
        time.sleep(1)
        sys.exit(0)
    
    def _run_command_with_output(self, command, output_file, description=None, show_progress=True, timeout=None):
        """Run a command and display real-time output while saving full output to file"""
        if description:
            print(f"{Colors.CYAN}[+] {description}{Colors.RESET}")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save command to output file
        with open(output_file, 'a') as f:
            f.write(f"\n\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"COMMAND: {command}\n")
            f.write(f"DESCRIPTION: {description}\n\n")
        
        # Run command and capture output
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        # Thread to read and display output
        def read_output():
            for line in iter(process.stdout.readline, ''):
                # Save to file
                with open(output_file, 'a') as f:
                    f.write(line)
                
                # Display in terminal (can be customized per tool)
                print(line.rstrip())
            process.stdout.close()
        
        # Start thread to read output
        output_thread = threading.Thread(target=read_output)
        output_thread.daemon = True
        output_thread.start()
        
        # Wait for process to complete with timeout if specified
        try:
            return_code = process.wait(timeout=timeout)
            output_thread.join(timeout=1)  # Give thread time to finish
            return return_code == 0
        except subprocess.TimeoutExpired:
            process.kill()
            output_thread.join(timeout=1)
            print(f"\n{Colors.YELLOW}[!] Command timed out after {timeout} seconds{Colors.RESET}")
            return False
    
    def _run_rustscan(self):
        """Run rustscan for port scanning"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/8] Running rustscan for port scanning...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract IP from URL
        ip_match = re.search(r'https?://([^/:]+)', self.target)
        if ip_match:
            ip = ip_match.group(1)
        else:
            ip = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        
        rustscan_file = os.path.join(self.output_dir, "rustscan.txt")
        hint_ports = get_hint_ports()
        if shutil.which("rustscan"):
            scan_command = f"rustscan -a {ip} --range 1-65535 --ulimit 5000 -b 500 -t 2000"
        else:
            if hint_ports:
                scan_command = f"nmap -sT -sV --version-light -n -Pn --open -T4 --max-retries 0 --host-timeout 45s -p{hint_ports} {ip}"
            else:
                scan_command = f"nmap -Pn -sV -O -T4 --open -p- {ip}"
        success = self._run_command_with_output(
            scan_command,
            rustscan_file,
            "Port scanning with rustscan"
        )
        
        # Extract open ports from rustscan output
        if success and os.path.exists(rustscan_file):
            with open(rustscan_file, 'r') as f:
                rustscan_data = f.read()
            
            # Extract open ports
            port_matches = re.findall(r'Open ' + re.escape(ip) + r':(\d+)', rustscan_data)
            self.open_ports = set(int(port) for port in port_matches)  # Using set to avoid duplicates
            
            # Extract port table from nmap output
            port_table = []
            port_table_pattern = r'(\d+/tcp\s+open\s+\w+\s+syn-ack ttl \d+)'
            table_matches = re.findall(port_table_pattern, rustscan_data)
            
            if table_matches:
                print("\nPORT     STATE SERVICE REASON")
                for match in table_matches:
                    print(match)
            
            # Extract MAC address if available
            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]+) \((.*?)\)', rustscan_data)
            if mac_match:
                print(f"MAC Address: {mac_match.group(1)} ({mac_match.group(2)})")
            
            if self.open_ports:
                print(f"\n{Colors.GREEN}[+] Open ports discovered: {', '.join(map(str, sorted(self.open_ports)))}{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}[!] No open ports found{Colors.RESET}")
    
    def _check_web_servers(self):
        """Check for web servers on open ports using curl"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/8] Checking for web servers...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract IP from URL
        ip_match = re.search(r'https?://([^/:]+)', self.target)
        if ip_match:
            ip = ip_match.group(1)
        else:
            ip = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        
        web_check_file = os.path.join(self.output_dir, "web_check.txt")
        
        # Check all open ports for web servers
        found_web_server = False
        results = []
        
        for port in sorted(self.open_ports):  # Sort for consistent output
            try:
                result = subprocess.run(
                    ["curl", "-s", "-I", "--max-time", "2", f"http://{ip}:{port}"],
                    capture_output=True, text=True, timeout=3
                )
                status_line = result.stdout.splitlines()[0] if result.stdout else ""
                if "HTTP/" in status_line:
                    results.append(f"Port {port}: {status_line.strip()}")
                    self.web_ports.add(port)  # Using set to avoid duplicates
                    found_web_server = True
            except (subprocess.TimeoutExpired, Exception):
                continue
        
        # Save results to file
        with open(web_check_file, 'w') as f:
            f.write("Web Server Detection Results:\n\n")
            if results:
                f.write("\n".join(results))
            else:
                f.write("No web servers found.\n")
        
        # Display results
        if found_web_server:
            print(f"\n{Colors.GREEN}[+] Web servers detected:{Colors.RESET}")
            for entry in results:
                print(f"  {Colors.CYAN}{entry}{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}[!] No web servers found{Colors.RESET}")
    
    def _run_whatweb(self):
        """Run whatweb for technology detection"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/8] Running whatweb for technology detection...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        whatweb_file = os.path.join(self.output_dir, "whatweb.txt")
        self._run_command_with_output(
            f"whatweb {self.target} --log-json={os.path.join(self.output_dir, 'whatweb.json')}",
            whatweb_file,
            "Technology detection with whatweb"
        )
    
    def _run_curl_info(self):
        """Run curl for detailed server information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/8] Running curl for detailed server information...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        curl_file = os.path.join(self.output_dir, "curl_info.txt")
        self._run_command_with_output(
            f"curl -s -I -L {self.target}",
            curl_file,
            "Detailed server information with curl"
        )
    
    def _run_host_info(self):
        """Run host command to get IP information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[5/8] Running host for IP information...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract domain from URL
        domain = self._extract_domain_from_url(self.target)
        
        if domain:
            host_file = os.path.join(self.output_dir, "host_info.txt")
            self._run_command_with_output(
                f"host {domain}",
                host_file,
                "IP information with host command"
            )
        else:
            print(f"{Colors.YELLOW}[!] Could not extract domain from URL. Skipping host command.{Colors.RESET}")
    
    def _run_subfinder(self):
        """Run subfinder for subdomain enumeration"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[6/8] Running subfinder for subdomain enumeration...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract domain from URL
        domain = self._extract_domain_from_url(self.target)
        
        if domain:
            subfinder_file = os.path.join(self.output_dir, "subfinder.txt")
            self._run_command_with_output(
                f"subfinder -d {domain} -silent",
                subfinder_file,
                "Subdomain enumeration with subfinder"
            )
        else:
            print(f"{Colors.YELLOW}[!] Could not extract domain from URL. Skipping subfinder.{Colors.RESET}")
    
    def _run_ffuf(self):
        """Run directory enumeration with ffuf"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[7/8] Running directory enumeration with ffuf...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract IP from URL
        ip_match = re.search(r'https?://([^/:]+)', self.target)
        if ip_match:
            ip = ip_match.group(1)
        else:
            ip = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Check if we have web ports
        if not self.web_ports:
            print(f"{Colors.YELLOW}[!] No web ports found. Skipping directory enumeration.{Colors.RESET}")
            return
        
        ffuf_file = os.path.join(self.output_dir, "ffuf.txt")
        
        # Create output directory for ffuf results
        ffuf_outdir = os.path.join(self.output_dir, "ffuf_results")
        os.makedirs(ffuf_outdir, exist_ok=True)
        
        # Run ffuf for each web port
        for port in sorted(self.web_ports):  # Sort for consistent output
            print(f"\n{Colors.CYAN}[+] Running ffuf on port {port}...{Colors.RESET}")
            
            port_ffuf_file = os.path.join(ffuf_outdir, f"ffuf_port_{port}.txt")
            
            # Set URL based on mode
            if self.ffuf_mode == "1":
                url = f"http://{ip}:{port}/"
                mode_desc = "Subdomain fuzzing"
                extra_args = ["-H", "Host: FUZZ"]
            else:
                url = f"http://{ip}:{port}/FUZZ"
                mode_desc = "Path fuzzing"
                extra_args = ["-e", self.file_extensions, "-recursion", "-recursion-depth", "2", "-ac", "-fc", "404"]
            
            # Run ffuf command
            command = [
                "ffuf",
                "-u", url,
                "-w", self.wordlist,
                "-t", "40",
                "-mc", "200,301,302,307,401,403,405,500",
                "-o", port_ffuf_file,
                *extra_args
            ]
            
            # Run command and capture output
            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Save results to file
                with open(port_ffuf_file, 'w') as f:
                    f.write(f"FFUF Results for {url}\n")
                    f.write(f"Mode: {mode_desc}\n")
                    f.write(f"Wordlist: {self.wordlist}\n\n")
                    
                    for line in process.stdout.splitlines():
                        if "[Status:" in line:
                            f.write(line + "\n")
                            print(line)
                    
                    if process.stderr:
                        f.write("\nErrors:\n")
                        f.write(process.stderr)
                
                # Append summary to main ffuf file
                with open(ffuf_file, 'a') as f:
                    f.write(f"\n\n=== PORT {port} ===\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Mode: {mode_desc}\n")
                    
                    for line in process.stdout.splitlines():
                        if "[Status:" in line:
                            f.write(line + "\n")
            
            except KeyboardInterrupt:
                print(f"\n{Colors.RED}[!] FFUF interrupted by user.{Colors.RESET}")
                continue
            except Exception as e:
                print(f"\n{Colors.RED}[!] Error running FFUF: {str(e)}{Colors.RESET}")
                continue
    
    def _run_nikto(self):
        """Run nikto for vulnerability scanning"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[8/8] Running nikto for vulnerability scanning...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        nikto_file = os.path.join(self.output_dir, "nikto.txt")
        self._run_command_with_output(
            f"nikto -h {self.target}",
            nikto_file,
            "Web vulnerability scanning with nikto",
            timeout=600
        )
    
    def _extract_domain_from_url(self, url):
        """Extract domain from URL"""
        domain_pattern = r'https?://([^/]+)'
        match = re.search(domain_pattern, url)
        return match.group(1) if match else None
    
    def _generate_summary(self):
        """Generate a clean summary of web application reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                 WEB APPLICATION RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Display open ports
        if self.open_ports:
            print(f"{Colors.YELLOW}[+] Open Ports:{Colors.RESET} {', '.join(map(str, sorted(self.open_ports)))}")
        else:
            print(f"{Colors.RED}[!] No open ports found{Colors.RESET}")
        
        # Display web ports
        if self.web_ports:
            print(f"{Colors.YELLOW}[+] Web Servers:{Colors.RESET} Ports {', '.join(map(str, sorted(self.web_ports)))}")
        
        # Parse whatweb results
        whatweb_json = os.path.join(self.output_dir, "whatweb.json")
        technologies = []
        if os.path.exists(whatweb_json):
            try:
                with open(whatweb_json, 'r') as f:
                    whatweb_data = json.load(f)
                
                # Extract technologies
                plugins = whatweb_data.get('plugins', {})
                for plugin, details in plugins.items():
                    if isinstance(details, dict) and details.get('version'):
                        technologies.append(f"{plugin} {details['version']}")
                    else:
                        technologies.append(plugin)
                
                if technologies:
                    print(f"{Colors.YELLOW}[+] Technologies:{Colors.RESET} {', '.join(technologies[:5])}" + 
                          (f" and {len(technologies) - 5} more..." if len(technologies) > 5 else ""))
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        
        # Parse ffuf results
        ffuf_file = os.path.join(self.output_dir, "ffuf.txt")
        directories = []
        if os.path.exists(ffuf_file):
            with open(ffuf_file, 'r') as f:
                ffuf_data = f.read()
            
            # Extract directories
            dir_matches = re.findall(r'(\S+)\s+\[Status: \d+\]', ffuf_data)
            if dir_matches:
                directories = [match for match in dir_matches if not match.startswith('FUZZ')]
                print(f"{Colors.YELLOW}[+] Directories:{Colors.RESET} {len(directories)} found")
        
        # Parse nikto results
        nikto_file = os.path.join(self.output_dir, "nikto.txt")
        vulnerabilities = []
        if os.path.exists(nikto_file):
            with open(nikto_file, 'r') as f:
                nikto_data = f.read()
            
            # Extract vulnerabilities
            vuln_matches = re.findall(r'\+ (OSVDB|CVE): (.+)', nikto_data)
            if vuln_matches:
                vulnerabilities = [f"{match[0]}: {match[1]}" for match in vuln_matches]
                print(f"{Colors.RED}[!] Vulnerabilities:{Colors.RESET} {len(vulnerabilities)} found")
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute web application reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Prompt for FFUF mode and wordlist
        print(f"\n{Colors.CYAN}[+] FFUF Configuration{Colors.RESET}")
        print(f"{Colors.WHITE}[1] Subdomain fuzzing (http://FUZZ.localhost:<port>){Colors.RESET}")
        print(f"{Colors.WHITE}[2] Path fuzzing (http://localhost:<port>/FUZZ){Colors.RESET}")
        
        try:
            self.ffuf_mode = input(f"{Colors.WHITE}[?] Select fuzzing mode (default = 2): {Colors.RESET}").strip()
            if not self.ffuf_mode:
                self.ffuf_mode = "2"
        except (EOFError, KeyboardInterrupt):
            self.ffuf_mode = "2"
            print(f"\n{Colors.YELLOW}[!] Using default mode (path fuzzing){Colors.RESET}")
        
        try:
            use_default = input(f"{Colors.WHITE}[?] Use default wordlist ({self.wordlist})? [y/n]: {Colors.RESET}").strip().lower()
            if use_default == 'n':
                self.wordlist = input(f"{Colors.WHITE}[*] Enter custom wordlist path: {Colors.RESET}").strip()
                if not os.path.exists(self.wordlist):
                    print(f"{Colors.RED}[!] Wordlist path not found. Using default.{Colors.RESET}")
                    self.wordlist = ensure_wordlists(["seclists_web"])["seclists_web"]
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}[!] Using default wordlist{Colors.RESET}")
        
        # Run all web application reconnaissance tools
        self._run_rustscan()
        self._check_web_servers()
        self._run_whatweb()
        self._run_curl_info()
        self._run_host_info()
        self._run_subfinder()
        self._run_ffuf()
        self._run_nikto()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Web application reconnaissance completed successfully!{Colors.RESET}")
        print(f"{Colors.CYAN}[+] Full results saved to: {self.output_dir}{Colors.RESET}")
        
        # Wait for user input before returning
        try:
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        except EOFError:
            # Handle Ctrl+D
            print(f"\n{Colors.YELLOW}[!] EOF detected. Returning to reconnaissance menu...{Colors.RESET}")
            time.sleep(1)
            sys.exit(0)

if __name__ == "__main__":
    try:
        target = sys.argv[1] if len(sys.argv) > 1 else ""
        if not target:
            print(f"{Colors.RED}[!] No target provided{Colors.RESET}")
            sys.exit(1)
            
        recon = WebappRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)
