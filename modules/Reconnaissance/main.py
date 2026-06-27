#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import sys
import time
import importlib.util

# Get the root directory (two levels up from this file)
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load the root main.py file for Colors class
main_py_path = os.path.join(root_dir, "main.py")
if os.path.exists(main_py_path):
    main_spec = importlib.util.spec_from_file_location("root_main", main_py_path)
    main_module = importlib.util.module_from_spec(main_spec)
    main_spec.loader.exec_module(main_module)
    
    Colors = main_module.Colors
else:
    # Fallback Colors definition if main.py is missing
    class Colors:
        RED = "\033[1;31m"
        GREEN = "\033[1;32m"
        YELLOW = "\033[1;33m"
        BLUE = "\033[1;34m"
        PURPLE = "\033[1;35m"
        CYAN = "\033[1;36m"
        WHITE = "\033[0;37m"
        BOLD = "\033[1m"
        UNDERLINE = "\033[4m"
        NC = "\033[0m"
        RESET = "\033[0m"


class ReconnaissanceMain:
    def __init__(self):
        self.banner = self._create_banner()
        
    def _create_banner(self):
        return f"""
{Colors.CYAN}╔{'═' * 80}╗
║{Colors.BOLD}                    RECONNAISSANCE MODULES{Colors.RESET}{' ' * 34}║
╠{'═' * 80}╣
{Colors.RESET}"""
    
    def _clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _display_menu(self):
        self._clear_screen()
        print(self.banner)
        print(f"{Colors.CYAN}{Colors.BOLD}Select a reconnaissance type:{Colors.RESET}")
        print()
        print(f"{Colors.YELLOW}1){Colors.RESET} {Colors.BOLD}Passive Reconnaissance{Colors.RESET}")
        print(f"{Colors.YELLOW}2){Colors.RESET} {Colors.BOLD}Active Reconnaissance{Colors.RESET}")
        print(f"{Colors.YELLOW}3){Colors.RESET} {Colors.BOLD}Network Reconnaissance{Colors.RESET}")
        print(f"{Colors.YELLOW}4){Colors.RESET} {Colors.BOLD}Web Application Reconnaissance{Colors.RESET}")
        print(f"{Colors.YELLOW}0){Colors.RESET} {Colors.BOLD}Back to Main Menu{Colors.RESET}")
        print()
        print(f"{Colors.CYAN}{Colors.BOLD}Enter your choice [0-4]: {Colors.RESET}", end=" ")

    def _get_target_input(self, recon_type):
        self._clear_screen()
        print(self.banner)
        print(f"{Colors.CYAN}{recon_type}{Colors.RESET}")
        print()
        
        prompts = {
            "Passive Reconnaissance": "Enter target domain or IP: ",
            "Active Reconnaissance": "Enter target IP or range: ",
            "Network Reconnaissance": "Enter network range (e.g., 192.168.1.0/24): ",
            "Web Application Reconnaissance": "Enter target URL (e.g., https://example.com): ",
        }

        prompt = prompts.get(recon_type, "Enter target: ")
        print(f"{Colors.CYAN}{prompt}{Colors.RESET}", end="")
        target = input().strip()
        
        if not target:
            print(f"{Colors.RED}Target cannot be empty. Please try again.{Colors.RESET}")
            time.sleep(2)
            return self._get_target_input(recon_type)
        
        return target
    
    def _confirm_execution(self, recon_type, target):
        self._clear_screen()
        print(self.banner)
        print(f"{Colors.CYAN}Execution Summary:{Colors.RESET}")
        print()
        print(f"{Colors.YELLOW}Reconnaissance Type:{Colors.RESET} {recon_type}")
        print(f"{Colors.YELLOW}Target:{Colors.RESET} {target}")
        print()
        
        print(f"{Colors.RED}WARNING: Only use this framework on systems you have permission to test.{Colors.RESET}")
        print()
        print(f"{Colors.CYAN}Do you want to proceed? [y/N]:{Colors.RESET}", end="")
        
        choice = input().strip().lower()
        return choice == 'y'
    
    def run(self):
        while True:
            try:
                self._display_menu()
                choice = input().strip()
                
                if choice == "0":
                    return  # Back to main menu
                
                recon_types = {
                    "1": ("Passive Reconnaissance", "passive_recon", "PassiveRecon"),
                    "2": ("Active Reconnaissance", "active_recon", "ActiveRecon"),
                    "3": ("Network Reconnaissance", "network_recon", "NetworkRecon"),
                    "4": ("Web Application Reconnaissance", "webapp_recon", "WebappRecon"),
                }

                if choice not in recon_types:
                    print(f"{Colors.RED}Invalid choice. Please select a valid option [0-4].{Colors.RESET}")
                    time.sleep(2)
                    continue

                recon_name, module_name, class_name = recon_types[choice]
                target = self._get_target_input(recon_name)
                if not self._confirm_execution(recon_name, target):
                    continue

                # Dynamically import the appropriate module and class
                module_path = os.path.join(os.path.dirname(__file__), f"{module_name}.py")
                if not os.path.exists(module_path):
                    print(f"{Colors.RED}[!] Module file not found: {module_path}{Colors.RESET}")
                    time.sleep(2)
                    continue

                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                ReconClass = getattr(module, class_name)
                recon_instance = ReconClass(target)
                recon_instance.run()

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Returning to main menu...{Colors.RESET}")
                time.sleep(1)
                return
            except EOFError:
                print(f"\n{Colors.YELLOW}Returning to main menu...{Colors.RESET}")
                time.sleep(1)
                return
            except Exception as e:
                print(f"{Colors.RED}[!] Error occurred: {e}{Colors.RESET}")
                time.sleep(2)

if __name__ == "__main__":
    ReconnaissanceMain().run()
