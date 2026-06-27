#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import os
import subprocess
import sys

# Color codes
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

# Quotes for each option
quotes = [
    "Auto-full-Swep: Changing identities like digital chameleons",
    "Reconnaissance: Knowing the battlefield wins half the war",
    "Vulnerability Scanning: Finding cracks in the armor",
    "Exploitation: Turning weaknesses into opportunities",
    "Password Cracking: When brute force meets persistence",
    "Reverse Shell Generator: Opening backdoors to possibilities",
    "Tools: The right instrument for every mission"
]

def show_menu():
    os.system("clear")
    print(f"{Colors.CYAN}==============================================================")
    print(f"{Colors.GREEN}__     ___ ____  ____  _____ ___     ____   ___  ____  _____ ")
    print(f"{Colors.GREEN}\\ \\   / (_) ___||  _ \\| ____|_ _|   |  _ \\ / _ \\|  _ \\| ____|")
    print(f"{Colors.GREEN} \\ \\ / /| \\___ \\| |_) |  _|  | |____| | | | | | | | | |  _|  ")
    print(f"{Colors.GREEN}  \\ V / | |___) |  _ <| |___ | |____| |_| | |_| | |_| | |___ ")
    print(f"{Colors.GREEN}   \\_/  |_|____/|_| \\_\\_____|___|   |____/ \\___/|____/|_____|")
    print(f"{Colors.CYAN}                    V I R E X   C O R E                      ")
    print(f"{Colors.CYAN}==============================================================")
    print(f"{Colors.BLUE}|                     V I R E X   C O R E                      |")
    print(f"{Colors.YELLOW}|                \"Automation at Warp Speed\"                    |")
    print(f"{Colors.CYAN}==============================================================")
    print(f"{Colors.PURPLE}======================= {Colors.WHITE}MAIN MENU {Colors.PURPLE}=============================")
    print(f"{Colors.GREEN}1){Colors.WHITE} Auto-full-Swep")
    print(f"{Colors.GREEN}2){Colors.WHITE} Reconnaissance")
    print(f"{Colors.GREEN}3){Colors.WHITE} Vulnerability Scanning")
    print(f"{Colors.GREEN}4){Colors.WHITE} Exploitation")
    print(f"{Colors.GREEN}5){Colors.WHITE} Password Cracking")
    print(f"{Colors.GREEN}6){Colors.WHITE} Reverse Shell Generator")
    print(f"{Colors.GREEN}7){Colors.WHITE} Tools")
    print(f"{Colors.RED}0){Colors.WHITE} Exit")
    print(f"{Colors.CYAN}==============================================================")
    return input(f"{Colors.YELLOW}[?] Select an option: {Colors.NC}")

def execute_script(option):
    modules = {
        "1": ("modules/Auto-full-Swep/main.py", quotes[0]),
        "2": ("modules/Reconnaissance/main.py", quotes[1]),
        "3": ("modules/Vulnerability_scanning/main.py", quotes[2]),
        "4": ("modules/Exploitation/main.py", quotes[3]),
        "5": ("modules/Password_Cracking/main.py", quotes[4]),
        "6": ("modules/Reverse_shell/main.py", quotes[5]),
        "7": ("modules/Tools/main.py", quotes[6]),
    }

    if option == "0":
        print(f"\n{Colors.RED}Exiting Virex Core...{Colors.NC}")
        sys.exit(0)

    script_info = modules.get(option)
    if script_info:
        path, quote = script_info
        print(f"\n{Colors.YELLOW}{quote}{Colors.NC}")

        if not os.path.isfile(path):
            print(f"{Colors.RED}[!] Script not found: {path}{Colors.NC}")
            input("Press enter to continue...")
            return

        try:
            if path.endswith(".py"):
                subprocess.run(["python3", path], check=True)
            else:
                subprocess.run([path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!] Failed to run: {path}{Colors.NC}")
            print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Python3 interpreter not found. Please install Python 3.{Colors.NC}")
    else:
        print(f"\n{Colors.RED}Invalid option! Please select a number between 0-7.{Colors.NC}")

    input("Press enter to continue...")

if __name__ == "__main__":
    try:
        while True:
            choice = show_menu()
            execute_script(choice)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Ctrl+C detected. Exiting Virex Core...{Colors.NC}")
        sys.exit(0)
