#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import sys
import socket
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recon_deps import ensure_commands, ensure_python_packages, get_output_base

ensure_commands(["telnet"])
ensure_python_packages(["paramiko", "pexpect", "requests"])

import ftplib
import paramiko
import pexpect
import requests

from requests.auth import HTTPBasicAuth

# Default credentials
DEFAULT_CREDENTIALS = {
    "ftp": [
        ("anonymous", ""),
        ("ftp", "ftp"),
        ("admin", "1234"),
        ("admin", "admin"),
        ("root", "ftp")
    ],
    "ssh": [
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("pi", "raspberry"),
        ("user", "user"),
        ("user", "pass")
    ],
    "telnet": [
        ("admin", "admin"),
        ("admin", "1234"),
        ("root", "root"),
        ("root", "12345"),
        ("guest", "guest"),
        ("support", "support"),
        ("supervisor", "supervisor")
    ],
    "web": [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("tomcat", "tomcat"),
        ("wordpress", "admin"),
        ("joomla", "admin")
    ]
}

def check_ftp(ip, port):
    print(f"\n[+] Checking FTP on {ip}:{port}")
    for username, password in DEFAULT_CREDENTIALS["ftp"]:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, int(port), timeout=5)
            ftp.login(username, password)
            print(f"[✅] FTP login successful: {username}:{password}")
            ftp.quit()
            return
        except Exception as e:
            print(f"[❌] {username}:{password} failed")
    print("[-] No valid FTP credentials found.")

def check_ssh(ip, port):
    print(f"\n[+] Checking SSH on {ip}:{port}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for username, password in DEFAULT_CREDENTIALS["ssh"]:
        try:
            client.connect(ip, port=int(port), username=username, password=password, timeout=5)
            print(f"[✅] SSH login successful: {username}:{password}")
            client.close()
            return
        except Exception:
            print(f"[❌] {username}:{password} failed")
    print("[-] No valid SSH credentials found.")

def check_telnet(ip, port):
    print(f"\n[+] Checking Telnet on {ip}:{port}")
    for username, password in DEFAULT_CREDENTIALS["telnet"]:
        try:
            child = pexpect.spawn(f"telnet {ip} {port}", timeout=5)
            child.expect(["login:", pexpect.TIMEOUT])
            child.sendline(username)
            child.expect(["Password:", pexpect.TIMEOUT])
            child.sendline(password)
            index = child.expect(["Login incorrect", "#", ">", pexpect.EOF, pexpect.TIMEOUT])
            if index in [1, 2]:  # Shell prompt
                print(f"[✅] Telnet login successful: {username}:{password}")
                child.close()
                return
            else:
                print(f"[❌] {username}:{password} failed")
                child.close()
        except Exception:
            print(f"[❌] {username}:{password} error/timeout")
    print("[-] No valid Telnet credentials found.")

def check_web(ip, port):
    print(f"\n[+] Checking Web Interface on {ip}:{port}")
    url = f"http://{ip}:{port}"
    for username, password in DEFAULT_CREDENTIALS["web"]:
        try:
            response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5)
            if response.status_code == 200:
                print(f"[✅] Web login successful: {username}:{password}")
                return
            else:
                print(f"[❌] {username}:{password} => HTTP {response.status_code}")
        except Exception:
            print(f"[❌] {username}:{password} error/timeout")
    print("[-] No valid Web credentials found.")

def main():
    if len(sys.argv) < 3:
        print("Usage: ./check_defaults.py ftp=21 ssh=22 telnet=23 web=80 <target_ip>")
        sys.exit(1)

    ip = sys.argv[-1]
    services = sys.argv[1:-1]

    for service_def in services:
        if '=' not in service_def:
            print(f"Invalid format: {service_def}")
            continue
        service, port = service_def.split("=")
        service = service.lower()
        if service == "ftp":
            check_ftp(ip, port)
        elif service == "ssh":
            check_ssh(ip, port)
        elif service == "telnet":
            check_telnet(ip, port)
        elif service == "web":
            check_web(ip, port)
        else:
            print(f"Unsupported service: {service}")

if __name__ == "__main__":
    main()
