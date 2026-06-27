#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import os
import sys
import subprocess
import re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, get_output_base

ensure_commands(["sqlmap", "curl"])

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"{CYAN}====================== SQLMap Scanner ======================{RESET}")

def run_sqlmap(target_url, output_dir, additional_params=None):
    """Run SQLMap with basic injection testing"""
    print(f"{YELLOW}[~] Running SQLMap on {target_url}...{RESET}")
    
    try:
        # Basic SQLMap command
        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",  # Never ask for user input
            "--random-agent",  # Use random User-Agent
            "--level", "1",  # Test level (1-5)
            "--risk", "1",   # Risk level (1-3)
            "--timeout", "30",
            "--retries", "2",
            "--output-dir", str(output_dir)
        ]
        
        # Add additional parameters if provided
        if additional_params:
            cmd.extend(additional_params)
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        return result.stdout, result.stderr, result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] SQLMap timed out{RESET}")
        return "", "Timeout", False
    except FileNotFoundError:
        print(f"{RED}[!] SQLMap not found. Please install sqlmap.{RESET}")
        return "", "Not found", False
    except Exception as e:
        print(f"{RED}[!] SQLMap error: {e}{RESET}")
        return "", str(e), False

def test_common_sql_injections(target_url):
    """Test for common SQL injection patterns using basic methods"""
    print(f"{YELLOW}[~] Testing common SQL injection patterns...{RESET}")
    
    # Common SQL injection payloads
    payloads = [
        "'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\",
        "1'", "1''", "1`", "1``", "1,", "1\"", "1\"\"", "1/", "1//", "1\\", "1\\\\",
        "'OR'1", "'OR'1'='1", "'OR'1'='1'--", "'OR'1'='1'/*",
        "1'OR'1'='1", "1'OR'1'='1'--", "1'OR'1'='1'/*",
        "admin'--", "admin'/*", "admin'#",
        "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "1; DROP TABLE users--", "'; DROP TABLE users--"
    ]
    
    vulnerable_params = []
    
    # Test if URL has parameters
    if '?' in target_url:
        base_url, params = target_url.split('?', 1)
        param_pairs = params.split('&')
        
        for param_pair in param_pairs:
            if '=' in param_pair:
                param_name, param_value = param_pair.split('=', 1)
                
                print(f"{CYAN}[+] Testing parameter: {param_name}{RESET}")
                
                # Test a few payloads on this parameter
                for payload in payloads[:5]:  # Test first 5 payloads
                    try:
                        # Build test URL
                        test_params = []
                        for pp in param_pairs:
                            if pp.startswith(param_name + '='):
                                test_params.append(f"{param_name}={payload}")
                            else:
                                test_params.append(pp)
                        
                        test_url = f"{base_url}?{'&'.join(test_params)}"
                        
                        # Make request
                        result = subprocess.run([
                            "curl", "-s", "--max-time", "10", test_url
                        ], capture_output=True, text=True)
                        
                        # Check for SQL error patterns
                        error_patterns = [
                            "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
                            "odbc", "jdbc", "sqlite", "postgresql", "warning: mysql",
                            "error in your sql syntax", "quoted string not properly terminated"
                        ]
                        
                        response = result.stdout.lower()
                        for pattern in error_patterns:
                            if pattern in response:
                                vulnerable_params.append({
                                    'parameter': param_name,
                                    'payload': payload,
                                    'error_pattern': pattern
                                })
                                print(f"{RED}[!] Potential SQL injection in {param_name} with payload: {payload}{RESET}")
                                break
                                
                    except:
                        continue
    
    return vulnerable_params

def extract_sqlmap_results(stdout, stderr):
    """Extract key findings from SQLMap output"""
    results = {
        'injectable_params': [],
        'databases': [],
        'tables': [],
        'vulnerabilities': [],
        'techniques': [],
        'dbms': None
    }
    
    lines = stdout.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Injectable parameters
        if 'parameter' in line.lower() and 'injectable' in line.lower():
            results['injectable_params'].append(line)
        
        # Database management system
        if 'back-end DBMS:' in line:
            dbms_match = re.search(r'back-end DBMS:\s*(.+)', line, re.IGNORECASE)
            if dbms_match:
                results['dbms'] = dbms_match.group(1)
        
        # Injection techniques
        if 'injection technique' in line.lower():
            results['techniques'].append(line)
        
        # Vulnerabilities found
        if any(vuln_keyword in line.lower() for vuln_keyword in ['vulnerable', 'injection', 'exploit']):
            results['vulnerabilities'].append(line)
        
        # Database names
        if 'available databases' in line.lower():
            # Next lines might contain database names
            continue
        
        # Table names
        if 'database table' in line.lower():
            results['tables'].append(line)
    
    return results

def display_results(results, basic_tests, target_url):
    """Display SQLMap scan results"""
    
    print(f"{GREEN}[+] Target: {target_url}{RESET}")
    print(f"{GREEN}[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    # DBMS Information
    if results['dbms']:
        print(f"{CYAN}=================== Database Management System ============={RESET}")
        print(f"{GREEN}[+] DBMS: {results['dbms']}{RESET}")
    
    # Injectable Parameters
    if results['injectable_params']:
        print(f"{CYAN}=================== Injectable Parameters =================={RESET}")
        for param in results['injectable_params']:
            print(f"{RED}[!] {param}{RESET}")
    
    # Injection Techniques
    if results['techniques']:
        print(f"{CYAN}=================== Injection Techniques ==================={RESET}")
        for technique in results['techniques']:
            print(f"{YELLOW}[+] {technique}{RESET}")
    
    # Vulnerabilities
    if results['vulnerabilities']:
        print(f"{CYAN}=================== Vulnerabilities Found =================={RESET}")
        for vuln in results['vulnerabilities'][:10]:  # Show first 10
            print(f"{RED}[!] {vuln}{RESET}")
    
    # Basic test results
    if basic_tests:
        print(f"{CYAN}================= Basic Injection Tests ===================={RESET}")
        for test in basic_tests:
            print(f"{RED}[!] Parameter '{test['parameter']}' vulnerable to: {test['payload']}{RESET}")
            print(f"{YELLOW}    Error pattern: {test['error_pattern']}{RESET}")
    
    # Summary
    print(f"{CYAN}========================= Summary ==========================={RESET}")
    print(f"{GREEN}[+] Injectable parameters: {len(results['injectable_params'])}{RESET}")
    print(f"{GREEN}[+] Basic test vulnerabilities: {len(basic_tests)}{RESET}")
    print(f"{GREEN}[+] Injection techniques found: {len(results['techniques'])}{RESET}")

def main():
    if len(sys.argv) < 2:
        print(f"{RED}Usage: {sys.argv[0]} <target_url> [port]{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} http://example.com/page.php?id=1{RESET}")
        print(f"{YELLOW}Example: {sys.argv[0]} example.com 3306{RESET}")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Format target URL if needed
    if not target.startswith(('http://', 'https://')):
        if port:
            target_url = f"http://{target}:{port}/"
        else:
            target_url = f"http://{target}/"
    else:
        target_url = target
    
    banner()
    
    # Create output directory
    output_dir = Path(get_output_base()) / "sqlmap"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run basic SQL injection tests first
    basic_tests = test_common_sql_injections(target_url)
    
    # Try to run SQLMap
    stdout, stderr, success = run_sqlmap(target_url, output_dir)
    
    if success:
        print(f"{GREEN}[✓] SQLMap scan completed successfully{RESET}")
        results = extract_sqlmap_results(stdout, stderr)
        
        # Save SQLMap output
        with open(output_dir / "sqlmap_output.txt", 'w') as f:
            f.write(f"SQLMap Output\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("STDOUT:\n")
            f.write(stdout)
            f.write("\n\nSTDERR:\n")
            f.write(stderr)
    else:
        print(f"{YELLOW}[!] SQLMap failed or not available, showing basic test results...{RESET}")
        results = {
            'injectable_params': [],
            'databases': [],
            'tables': [],
            'vulnerabilities': [],
            'techniques': [],
            'dbms': None
        }
        
        # Save basic test results
        with open(output_dir / "basic_sql_tests.txt", 'w') as f:
            f.write(f"Basic SQL Injection Tests\n")
            f.write(f"Target: {target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for test in basic_tests:
                f.write(f"Parameter: {test['parameter']}\n")
                f.write(f"Payload: {test['payload']}\n")
                f.write(f"Error Pattern: {test['error_pattern']}\n\n")
    
    # Display results
    display_results(results, basic_tests, target_url)
    
    print(f"{CYAN}============================================================{RESET}")
    print(f"{GREEN}[!] SQL injection testing completed. Results saved in {output_dir}{RESET}")
    
    # Return appropriate exit code
    if results['injectable_params'] or basic_tests:
        print(f"{RED}[!] SQL injection vulnerabilities found - manual investigation required{RESET}")
    else:
        print(f"{GREEN}[+] No SQL injection vulnerabilities detected{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] SQLMap scan interrupted by user{RESET}")
        sys.exit(1)
