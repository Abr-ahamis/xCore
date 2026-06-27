#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import sys
import time
import subprocess
import re
import json
import threading
import signal
import shutil
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Auto-full-Swep"))
from recon_deps import ensure_commands, get_output_base

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

class PassiveRecon:
    def __init__(self, target):
        ensure_commands(["whois", "dig", "nslookup", "theHarvester", "amass", "subfinder", "curl", "shodan"])
        self.target = target
        self.output_base = get_output_base()
        self.output_dir = self._create_output_dir(target)
        
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
    
    def _run_whois(self):
        """Run whois to get domain registration information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/8] Running whois lookup...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        whois_file = os.path.join(self.output_dir, "whois.txt")
        self._run_command_with_output(
            f"whois {self.target}",
            whois_file,
            "Domain registration information lookup"
        )
    
    def _run_dns_lookup(self):
        """Run DNS lookups to get DNS records"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/8] Running DNS lookups...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        dns_file = os.path.join(self.output_dir, "dns_lookup.txt")
        self._run_command_with_output(
            f"dig {self.target} ANY +short",
            dns_file,
            "DNS records lookup"
        )
    
    def _run_nslookup(self):
        """Run nslookup for additional DNS information"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/8] Running nslookup...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        nslookup_file = os.path.join(self.output_dir, "nslookup.txt")
        self._run_command_with_output(
            f"nslookup {self.target}",
            nslookup_file,
            "NS lookup for additional DNS information"
        )
    
    def _run_theharvester(self):
        """Run theHarvester to gather emails, subdomains, and hosts"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/8] Running theHarvester...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        harvester_file = os.path.join(self.output_dir, "theharvester.txt")
        self._run_command_with_output(
            f"theHarvester -d {self.target} -l 100 -b all",
            harvester_file,
            "Email, subdomain, and host gathering"
        )
    
    def _run_amass(self):
        """Run amass for subdomain enumeration"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[5/8] Running amass...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        amass_file = os.path.join(self.output_dir, "amass.txt")
        self._run_command_with_output(
            f"amass enum -passive -d {self.target}",
            amass_file,
            "Subdomain enumeration"
        )
    
    def _run_subfinder(self):
        """Run subfinder for additional subdomain enumeration"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[6/8] Running subfinder...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        subfinder_file = os.path.join(self.output_dir, "subfinder.txt")
        self._run_command_with_output(
            f"subfinder -d {self.target} -silent",
            subfinder_file,
            "Additional subdomain enumeration"
        )
    
    def _run_curl_headers(self):
        """Run curl for HTTP headers"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[7/8] Running curl for HTTP headers...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Add http:// or https:// if not present
        url = self.target
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        curl_file = os.path.join(self.output_dir, "curl_headers.txt")
        self._run_command_with_output(
            f"curl -I {url}",
            curl_file,
            "HTTP headers retrieval"
        )
    
    def _run_shodan(self):
        """Run Shodan if available"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[8/8] Running Shodan lookup...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        shodan_file = os.path.join(self.output_dir, "shodan.txt")
        self._run_command_with_output(
            f"shodan host {self.target}",
            shodan_file,
            "Shodan host information lookup"
        )
    
    def _generate_summary(self):
        """Generate a clean summary of passive reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                    PASSIVE RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Parse whois information
        whois_file = os.path.join(self.output_dir, "whois.txt")
        if os.path.exists(whois_file):
            with open(whois_file, 'r') as f:
                whois_data = f.read()
            
            # Extract key information
            registrar = self._extract_whois_field(whois_data, r"Registrar: (.+)")
            creation_date = self._extract_whois_field(whois_data, r"Creation Date: (.+)")
            expiration_date = self._extract_whois_field(whois_data, r"Registry Expiry Date: (.+)")
            
            if registrar:
                print(f"{Colors.YELLOW}[+] Domain Registrar:{Colors.RESET} {registrar}")
            if creation_date:
                print(f"{Colors.YELLOW}[+] Domain Created:{Colors.RESET} {creation_date}")
            if expiration_date:
                print(f"{Colors.YELLOW}[+] Domain Expires:{Colors.RESET} {expiration_date}")
        
        # Parse DNS information
        dns_file = os.path.join(self.output_dir, "dns_lookup.txt")
        if os.path.exists(dns_file):
            with open(dns_file, 'r') as f:
                dns_data = f.read()
            
            # Count record types
            a_records = dns_data.count('\n') if dns_data else 0
            if a_records > 0:
                print(f"{Colors.YELLOW}[+] DNS Records:{Colors.RESET} {a_records} records found")
        
        # Parse theHarvester information
        harvester_file = os.path.join(self.output_dir, "theharvester.txt")
        if os.path.exists(harvester_file):
            with open(harvester_file, 'r') as f:
                harvester_data = f.read()
            
            # Extract emails and subdomains
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', harvester_data)
            subdomains = re.findall(r'[\w\.-]+\.' + re.escape(self.target), harvester_data)
            
            if emails:
                print(f"{Colors.YELLOW}[+] Email Addresses:{Colors.RESET} {len(emails)} found")
            if subdomains:
                print(f"{Colors.YELLOW}[+] Subdomains:{Colors.RESET} {len(subdomains)} found")
        
        # Parse amass information
        amass_file = os.path.join(self.output_dir, "amass.txt")
        if os.path.exists(amass_file):
            with open(amass_file, 'r') as f:
                amass_data = f.read()
            
            # Count subdomains
            amass_subdomains = len([line for line in amass_data.split('\n') if line.strip()])
            if amass_subdomains > 0:
                print(f"{Colors.YELLOW}[+] Amass Subdomains:{Colors.RESET} {amass_subdomains} found")
        
        # Parse subfinder information
        subfinder_file = os.path.join(self.output_dir, "subfinder.txt")
        if os.path.exists(subfinder_file):
            with open(subfinder_file, 'r') as f:
                subfinder_data = f.read()
            
            # Count subdomains
            subfinder_subdomains = len([line for line in subfinder_data.split('\n') if line.strip()])
            if subfinder_subdomains > 0:
                print(f"{Colors.YELLOW}[+] Subfinder Subdomains:{Colors.RESET} {subfinder_subdomains} found")
        
        # Parse curl headers
        curl_file = os.path.join(self.output_dir, "curl_headers.txt")
        if os.path.exists(curl_file):
            with open(curl_file, 'r') as f:
                curl_data = f.read()
            
            # Extract server and security headers
            server = re.search(r'Server: (.+)', curl_data)
            if server:
                print(f"{Colors.YELLOW}[+] Web Server:{Colors.RESET} {server.group(1)}")
            
            # Check for security headers
            security_headers = ['Content-Security-Policy', 'X-Content-Type-Options', 
                               'X-Frame-Options', 'X-XSS-Protection', 
                               'Strict-Transport-Security']
            
            missing_headers = []
            for header in security_headers:
                if header not in curl_data:
                    missing_headers.append(header)
            
            if missing_headers:
                print(f"{Colors.RED}[!] Missing Security Headers:{Colors.RESET} {', '.join(missing_headers)}")
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def _extract_whois_field(self, text, pattern):
        """Extract a field from whois output using regex"""
        matches = re.findall(pattern, text)
        return matches[0] if matches else None
    
    def run(self):
        """Execute passive reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Run all passive reconnaissance tools
        self._run_whois()
        self._run_dns_lookup()
        self._run_nslookup()
        self._run_theharvester()
        self._run_amass()
        self._run_subfinder()
        self._run_curl_headers()
        self._run_shodan()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Passive reconnaissance completed successfully!{Colors.RESET}")
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
            
        recon = PassiveRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)
