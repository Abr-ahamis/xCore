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

class NetworkRecon:
    def __init__(self, target):
        ensure_commands(["arp-scan", "traceroute", "masscan"])
        self.target = target
        self.output_base = get_output_base()
        self.output_dir = self._create_output_dir(target)
        self.monitor_interface = None
        self.wifi_networks = []
        
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
    
    def _discover_devices(self):
        """Discover devices in the network"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[1/4] Discovering devices in the network...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        host_file = os.path.join(self.output_dir, "host_discovery.txt")
        self._run_command_with_output(
            f"sudo arp-scan {self.target}",
            host_file,
            "Host discovery using arp-scan (requires sudo)"
        )
        
        # Extract discovered hosts
        discovered_hosts = []
        if os.path.exists(host_file):
            with open(host_file, 'r') as f:
                host_data = f.read()
            
            # Extract live hosts
            host_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)', host_data)
            discovered_hosts = [match[0] for match in host_matches]
        
        return discovered_hosts
    
    def _scan_hosts(self, hosts):
        """Scan open ports on discovered hosts"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[2/4] Scanning open ports on discovered hosts...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        if not hosts:
            print(f"{Colors.YELLOW}[!] No hosts to scan{Colors.RESET}")
            return
        
        # Create a file to store all results
        all_hosts_file = os.path.join(self.output_dir, "all_hosts_scan.txt")
        
        # Scan each host
        for i, host in enumerate(hosts[:5]):  # Limit to first 5 hosts
            print(f"\n{Colors.CYAN}[+] Scanning host {i+1}/{len(hosts[:5])}: {host}{Colors.RESET}")
            
            host_file = os.path.join(self.output_dir, f"host_{host.replace('.', '_')}.txt")
            hint_ports = get_hint_ports()
            if shutil.which("rustscan"):
                scan_command = f"rustscan -a {host} --range 1-1000 --ulimit 5000 -b 500 -t 2000"
            else:
                if hint_ports:
                    scan_command = f"nmap -sT -sV --version-light -n -Pn --open -T4 --max-retries 0 --host-timeout 45s -p{hint_ports} {host}"
                else:
                    scan_command = f"nmap -Pn -sV -O -T4 --open -p- {host}"
            self._run_command_with_output(
                scan_command,
                host_file,
                f"Port scanning on host {host}"
            )
            
            # Append results to the all hosts file
            if os.path.exists(host_file):
                with open(host_file, 'r') as f:
                    host_data = f.read()
                
                with open(all_hosts_file, 'a') as f:
                    f.write(f"\n\n=== HOST: {host} ===\n")
                    f.write(host_data)
    
    def _run_traceroute(self):
        """Run traceroute to map network path"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[3/4] Running traceroute...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        # Extract a single IP from the network range
        target_ip = self._extract_ip_from_network(self.target)
        
        if target_ip:
            traceroute_file = os.path.join(self.output_dir, "traceroute.txt")
            self._run_command_with_output(
                f"sudo traceroute {target_ip}",
                traceroute_file,
                "Network path tracing (requires sudo)"
            )
        else:
            print(f"{Colors.YELLOW}[!] Could not extract a target IP from the network range. Skipping traceroute.{Colors.RESET}")
    
    def _run_masscan(self):
        """Run masscan for large-scale port scanning"""
        print(f"\n{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}[4/4] Running masscan...{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 80}{Colors.RESET}")
        
        masscan_file = os.path.join(self.output_dir, "masscan.txt")
        self._run_command_with_output(
            f"sudo masscan {self.target} -p1-1000 --rate=1000",
            masscan_file,
            "Large-scale port scanning with masscan (requires sudo)"
        )
    
    def _extract_ip_from_network(self, network):
        """Extract a single IP from a network range"""
        if '/' in network:
            # It's a CIDR notation
            base_ip = network.split('/')[0]
            return base_ip
        elif '-' in network:
            # It's a range
            start_ip = network.split('-')[0]
            return start_ip
        else:
            # It's a single IP
            return network
    
    def _generate_summary(self):
        """Generate a clean summary of network reconnaissance findings"""
        print(f"\n{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.MAGENTA}                    NETWORK RECONNAISSANCE SUMMARY{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}Target: {self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
        
        # Parse host discovery results
        host_file = os.path.join(self.output_dir, "host_discovery.txt")
        live_hosts = []
        if os.path.exists(host_file):
            with open(host_file, 'r') as f:
                host_data = f.read()
            
            # Extract live hosts
            host_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)', host_data)
            live_hosts = [match[0] for match in host_matches]
            
            if live_hosts:
                print(f"{Colors.YELLOW}[+] Live Hosts:{Colors.RESET} {len(live_hosts)} hosts found")
        
        # Parse masscan results
        masscan_file = os.path.join(self.output_dir, "masscan.txt")
        open_ports = []
        if os.path.exists(masscan_file):
            with open(masscan_file, 'r') as f:
                masscan_data = f.read()
            
            # Extract open ports
            port_matches = re.findall(r'Discovered open port (\d+)/tcp on ([\d.]+)', masscan_data)
            if port_matches:
                open_ports = [(match[1], int(match[0])) for match in port_matches]
                
                # Group by host
                hosts_ports = {}
                for host, port in open_ports:
                    if host not in hosts_ports:
                        hosts_ports[host] = []
                    hosts_ports[host].append(port)
                
                print(f"{Colors.YELLOW}[+] Open Ports:{Colors.RESET} Found on {len(hosts_ports)} hosts")
        
        print(f"{Colors.MAGENTA}{'═' * 80}{Colors.RESET}")
    
    def run(self):
        """Execute network reconnaissance with comprehensive tools"""
        # Set up signal handler for EOF (Ctrl+D)
        signal.signal(signal.SIGINT, self._handle_eof)
        
        print(f"{Colors.CYAN}[+] Output will be saved in: {self.output_dir}{Colors.RESET}")
        
        # Discover devices in the network
        discovered_hosts = self._discover_devices()
        
        # Scan open ports on discovered hosts
        self._scan_hosts(discovered_hosts)
        
        # Run other network reconnaissance tools
        self._run_traceroute()
        self._run_masscan()
        
        # Generate summary
        self._generate_summary()
        
        print(f"\n{Colors.GREEN}[✓] Network reconnaissance completed successfully!{Colors.RESET}")
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
            
        recon = NetworkRecon(target)
        recon.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}Operation cancelled by user. Returning to reconnaissance menu...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An unexpected error occurred: {str(e)}{Colors.RESET}")
        sys.exit(1)
