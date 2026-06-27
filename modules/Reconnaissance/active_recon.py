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
import shutil
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Auto-full-Swep"))
from recon_deps import ensure_commands, get_hint_ports, get_output_base

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

class ActiveRecon:
    def __init__(self, target):
        ensure_commands(["nmap", "curl", "searchsploit", "ssh-audit", "whatweb", "smbclient", "mysql"])
        self.target = target
        self.output_base = get_output_base()
        self.output_dir = self._create_output_dir(target)
        self.open_ports = []
        
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
    
    def _run_command_with_output(self, command, output_file, description=None, show_progress=True):
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
        
        # Wait for process to complete
        return_code = process.wait()
        output_thread.join(timeout=1)  # Give thread time to finish
        
        return return_code == 0
    
    def _run_rustscan(self):
        """Run rustscan for fast port scanning"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/6] Running rustscan for fast port scanning...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        rustscan_file = os.path.join(self.output_dir, "rustscan.txt")
        hint_ports = get_hint_ports()
        if shutil.which("rustscan"):
            scan_command = f"rustscan -a {self.target} --range 1-65535 --ulimit 5000 -b 500 -t 2000"
        else:
            if hint_ports:
                scan_command = f"nmap -sT -sV --version-light -n -Pn --open -T4 --max-retries 0 --host-timeout 45s -p{hint_ports} {self.target}"
            else:
                scan_command = f"nmap -Pn -sV -O -T4 --open -p- {self.target}"

        success = self._run_command_with_output(
            scan_command,
            rustscan_file,
            "Fast port scanning with rustscan"
        )
        
        # Extract open ports from rustscan output
        if success and os.path.exists(rustscan_file):
            with open(rustscan_file, 'r') as f:
                rustscan_data = f.read()
            
            # Extract open ports
            port_matches = re.findall(r'Open ' + re.escape(self.target) + r':(\d+)', rustscan_data)
            self.open_ports = [int(port) for port in port_matches]
            
            if self.open_ports:
                print(f"\n{Colors.GREEN}[+] Open ports discovered: {', '.join(map(str, self.open_ports))}{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}[!] No open ports found{Colors.RESET}")
    
    def _run_nmap(self):
        """Run detailed nmap scan on open ports"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/6] Running detailed nmap scan...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        if not self.open_ports:
            print(f"{Colors.YELLOW}[!] No open ports to scan with nmap{Colors.RESET}")
            return
        
        # Convert ports to nmap format
        ports_str = ','.join(map(str, self.open_ports))
        
        nmap_file = os.path.join(self.output_dir, "nmap.txt")
        self._run_command_with_output(
            f"nmap -sV -sC -O -p{ports_str} --open -T4 {self.target}",
            nmap_file,
            "Detailed nmap scan with service detection"
        )
    
    def _check_web_servers(self):
        """Check for web servers on open ports"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/6] Checking for web servers...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Common web ports
        web_ports = [port for port in self.open_ports if port in [80, 443, 8080, 8000, 8888, 8443, 3000, 5000, 9000]]
        
        if not web_ports:
            print(f"{Colors.YELLOW}[!] No common web ports found{Colors.RESET}")
            return
        
        web_check_file = os.path.join(self.output_dir, "web_check.txt")
        
        # Create command to check web servers
        commands = []
        for port in web_ports:
            commands.append(f"echo -e \"\\nChecking port {port}...\"; curl -s -I --max-time 2 http://{self.target}:{port} | head -n 1")
        
        command = ' && '.join(commands)
        self._run_command_with_output(
            command,
            web_check_file,
            "Web server detection"
        )
    
    def _run_vulnerability_scan(self):
        """Run vulnerability scan on open ports"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/6] Running vulnerability scan...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        if not self.open_ports:
            print(f"{Colors.YELLOW}[!] No open ports to scan for vulnerabilities{Colors.RESET}")
            return
        
        # Convert ports to nmap format
        ports_str = ','.join(map(str, self.open_ports))
        
        vuln_file = os.path.join(self.output_dir, "nmap_vuln.txt")
        self._run_command_with_output(
            f"nmap -sV --script vuln -p{ports_str} {self.target}",
            vuln_file,
            "Nmap vulnerability scan"
        )
    
    def _run_searchsploit(self):
        """Run searchsploit for exploits"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[5/6] Running searchsploit...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Parse nmap results to extract service information
        nmap_file = os.path.join(self.output_dir, "nmap.txt")
        services = []
        
        if os.path.exists(nmap_file):
            with open(nmap_file, 'r') as f:
                nmap_data = f.read()
            
            # Extract services
            service_matches = re.findall(r'(\d+)/tcp\s+open\s+([\w-]+)\s+(.*)', nmap_data)
            for port, service, info in service_matches:
                # Extract version if available
                version_match = re.search(r'(\d+\.\d+(\.\d+)?)', info)
                if version_match:
                    services.append(f"{service} {version_match.group(1)}")
                else:
                    services.append(service)
        
        searchsploit_file = os.path.join(self.output_dir, "searchsploit.txt")
        
        # Run searchsploit for each service
        if services:
            print(f"{Colors.CYAN}[+] Found services: {', '.join(services)}{Colors.RESET}")
            
            for service in services[:5]:  # Limit to first 5 services
                print(f"\n{Colors.YELLOW}[+] Searching exploits for: {service}{Colors.RESET}")
                self._run_command_with_output(
                    f"searchsploit {service}",
                    searchsploit_file,
                    f"Exploit search for {service}"
                )
        else:
            # Run general search if no services found
            self._run_command_with_output(
                f"searchsploit {self.target}",
                searchsploit_file,
                "Exploit search"
            )
    
    def _run_service_enumeration(self):
        """Run service-specific enumeration"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[6/6] Running service-specific enumeration...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Parse nmap results to identify services
        nmap_file = os.path.join(self.output_dir, "nmap.txt")
        services = []
        
        if os.path.exists(nmap_file):
            with open(nmap_file, 'r') as f:
                nmap_data = f.read()
            
            # Extract services
            service_matches = re.findall(r'(\d+)/tcp\s+open\s+([\w-]+)', nmap_data)
            services = [(int(port), service) for port, service in service_matches]
        
        # Run service-specific tools
        for port, service in services:
            if service.lower() in ['ssh', 'http', 'https', 'ftp', 'smb', 'mysql', 'mssql', 'postgresql']:
                enum_file = os.path.join(self.output_dir, f"enum_{service}_{port}.txt")
                
                if service.lower() == 'ssh':
                    self._run_command_with_output(
                        f"ssh-audit {self.target} -p {port}",
                        enum_file,
                        f"SSH enumeration on port {port}"
                    )
                elif service.lower() in ['http', 'https']:
                    url = f"https://{self.target}:{port}" if service.lower() == 'https' else f"http://{self.target}:{port}"
                    self._run_command_with_output(
                        f"whatweb {url}",
                        enum_file,
                        f"Web technology detection on port {port}"
                    )
                elif service.lower() == 'ftp':
                    self._run_command_with_output(
                        f"nmap --script ftp-anon -p {port} {self.target}",
                        enum_file,
                        f"FTP anonymous access check on port {port}"
                    )
                elif service.lower() == 'smb':
                    self._run_command_with_output(
                        f"smbclient -L //{self.target} -N",
                        enum_file,
                        f"SMB enumeration on port {port}"
                    )
                elif service.lower() == 'mysql':
                    self._run_command_with_output(
                        f"mysql --host={self.target} --port={port} --execute=\"SHOW DATABASES;\"",
                        enum_file,
                        f"MySQL enumeration on port {port}"
                    )
    
    def _generate_summary(self):
        """Generate a clean summary of active reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                     ACTIVE RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Display open ports
        if self.open_ports:
            print(f"{Colors.YELLOW}[+] Open Ports:{Colors.RESET} {', '.join(map(str, self.open_ports))}")
        else:
            print(f"{Colors.RED}[!] No open ports found{Colors.RESET}")
        
        # Parse nmap results
        nmap_file = os.path.join(self.output_dir, "nmap.txt")
        services = []
        if os.path.exists(nmap_file):
            with open(nmap_file, 'r') as f:
                nmap_data = f.read()
            
            # Extract services
            service_matches = re.findall(r'(\d+)/tcp\s+open\s+([\w-]+)\s+(.*)', nmap_data)
            for port, service, info in service_matches:
                services.append(f"{port}/{service}")
                
                # Highlight interesting services
                if service.lower() in ['ssh', 'http', 'https', 'ftp', 'smb', 'mysql', 'mssql', 'postgresql']:
                    print(f"{Colors.YELLOW}[+] Service:{Colors.RESET} {port}/{service} - {info.strip()}")
        
        # Parse vulnerability results
        vuln_file = os.path.join(self.output_dir, "nmap_vuln.txt")
        vulnerabilities = []
        if os.path.exists(vuln_file):
            with open(vuln_file, 'r') as f:
                vuln_data = f.read()
            
            # Extract CVEs
            cve_matches = re.findall(r'CVE-\d{4}-\d+', vuln_data)
            if cve_matches:
                vulnerabilities = list(set(cve_matches))  # Remove duplicates
                print(f"{Colors.RED}[!] Vulnerabilities:{Colors.RESET} {len(vulnerabilities)} CVEs found")
        
        # Parse web check results
        web_check_file = os.path.join(self.output_dir, "web_check.txt")
        web_ports = []
        if os.path.exists(web_check_file):
            with open(web_check_file, 'r') as f:
                web_data = f.read()
            
            # Extract web ports
            web_matches = re.findall(r'port (\d+).*?HTTP/\d\.\d+ \d+', web_data)
            if web_matches:
                web_ports = [int(port) for port in web_matches]
                print(f"{Colors.YELLOW}[+] Web Servers:{Colors.RESET} Ports {', '.join(map(str, web_ports))}")
        
        # Parse searchsploit results
        searchsploit_file = os.path.join(self.output_dir, "searchsploit.txt")
        exploits = []
        if os.path.exists(searchsploit_file):
            with open(searchsploit_file, 'r') as f:
                searchsploit_data = f.read()
            
            # Count exploits
            exploit_matches = re.findall(r'\| (.+) \|', searchsploit_data)
            if exploit_matches:
                exploits = exploit_matches
                print(f"{Colors.RED}[!] Exploits:{Colors.RESET} {len(exploits)} potential exploits found")
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute active reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Run all active reconnaissance tools
        self._run_rustscan()
        self._run_nmap()
        self._check_web_servers()
        self._run_vulnerability_scan()
        self._run_searchsploit()
        self._run_service_enumeration()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Active reconnaissance completed successfully!{Colors.RESET}")
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
            
        recon = ActiveRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)
