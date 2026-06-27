#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import getpass
import gzip
from pathlib import Path
from urllib.request import urlretrieve

RUSTSCAN_DEB_ZIP_URL = "https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip"

APT_PACKAGES = {
    "amass": "amass",
    "arp-scan": "arp-scan",
    "bloodhound-python": None,
    "curl": "curl",
    "dig": "dnsutils",
    "enum4linux": "enum4linux",
    "ffuf": "ffuf",
    "ftp": "ftp",
    "ftp-anon": "nmap",
    "gobuster": "gobuster",
    "host": "bind9-host",
    "hydra": "hydra",
    "ldapsearch": "ldap-utils",
    "masscan": "masscan",
    "msfconsole": "metasploit-framework",
    "mysql": "default-mysql-client",
    "nikto": "nikto",
    "nmap": "nmap",
    "nslookup": "dnsutils",
    "onesixtyone": "onesixtyone",
    "rdpscan": "rdpscan",
    "rpcclient": "samba-common-bin",
    "searchsploit": "exploitdb",
    "secretsdump.py": "impacket-scripts",
    "shodan": "shodan",
    "smbclient": "smbclient",
    "smbmap": "smbmap",
    "smtp-user-enum": "smtp-user-enum",
    "snmp-check": "snmpcheck",
    "snmpwalk": "snmp",
    "sqlmap": "sqlmap",
    "ssh-audit": "ssh-audit",
    "subfinder": "subfinder",
    "telnet": "telnet",
    "theHarvester": "theharvester",
    "traceroute": "traceroute",
    "vncviewer": "tigervnc-viewer",
    "vncsnapshot": "vncsnapshot",
    "whatweb": "whatweb",
    "whois": "whois",
    "wpscan": "wpscan",
    "xfreerdp": "freerdp2-x11",
}

PIP_PACKAGES = {
    "bloodhound-python": "bloodhound",
    "paramiko": "paramiko",
    "pexpect": "pexpect",
    "requests": "requests",
    "shodan": "shodan",
}

_APT_UPDATED = False

WORDLISTS = {
    "seclists_web": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "seclists_dns": [
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    "seclists_usernames": [
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ],
    "seclists_snmp": [
        "/usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
        "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
    ],
    "rockyou": [
        "/usr/share/wordlists/rockyou.txt",
    ],
    "fasttrack": [
        "/usr/share/wordlists/fasttrack.txt",
    ],
}


def get_output_base(preferred="/tmp/VirexCore"):
    path = Path(os.environ.get("OUTPUT_DIR", preferred))
    try:
        path.mkdir(parents=True, exist_ok=True)
        test_file = path / ".write_test"
        test_file.write_text("", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        return str(path)
    except PermissionError:
        fallback = Path(f"/tmp/VirexCore-{getpass.getuser()}")
        fallback.mkdir(parents=True, exist_ok=True)
        return str(fallback)


def get_hint_ports(env_name="XCORE_HINT_PORTS"):
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return ""

    ports = set()
    for token in re.split(r"[,\s]+", raw):
        if not token:
            continue
        if "-" in token:
            start, end = token.split("-", 1)
            if start.isdigit() and end.isdigit():
                start_i = int(start)
                end_i = int(end)
                if 0 < start_i <= end_i <= 65535:
                    ports.update(range(start_i, end_i + 1))
            continue
        if token.isdigit():
            port = int(token)
            if 0 < port <= 65535:
                ports.add(port)

    return ",".join(str(port) for port in sorted(ports))


def _run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def _sudo_prefix():
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo]
    return []


def _apt_available():
    return shutil.which("apt-get") is not None


def _apt_install(package):
    global _APT_UPDATED
    if not package or not _apt_available():
        return False
    prefix = _sudo_prefix()
    if not prefix and os.geteuid() != 0:
        return False
    try:
        if not _APT_UPDATED:
            _run(prefix + ["apt-get", "update"])
            _APT_UPDATED = True
        _run(prefix + ["apt-get", "install", "-y", package])
        return True
    except subprocess.CalledProcessError:
        return False


def _pip_install(package):
    try:
        _run([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False


def _install_rustscan():
    if shutil.which("rustscan"):
        return True
    prefix = _sudo_prefix()
    if not prefix and os.geteuid() != 0:
        return False

    with tempfile.TemporaryDirectory(prefix="xcore-rustscan-") as tmp:
        tmpdir = Path(tmp)
        zip_path = tmpdir / "rustscan.deb.zip"
        try:
            _run(["wget", RUSTSCAN_DEB_ZIP_URL, "-O", str(zip_path)])
        except subprocess.CalledProcessError:
            try:
                urlretrieve(RUSTSCAN_DEB_ZIP_URL, zip_path)
            except Exception:
                return False

        try:
            _run(["unzip", str(zip_path)], cwd=tmpdir)
        except subprocess.CalledProcessError:
            return False

        debs = sorted(tmpdir.glob("*.deb"))
        if not debs:
            return False

        try:
            _run(prefix + ["dpkg", "-i", str(debs[0])])
        except subprocess.CalledProcessError:
            try:
                _run(prefix + ["apt-get", "-f", "install", "-y"])
                _run(prefix + ["dpkg", "-i", str(debs[0])])
            except subprocess.CalledProcessError:
                return False

    return shutil.which("rustscan") is not None


def ensure_commands(commands):
    missing = []
    for command in commands:
        if shutil.which(command):
            continue
        print(f"[!] Missing dependency: {command}. Installing...")
        installed = _install_rustscan() if command == "rustscan" else _apt_install(APT_PACKAGES.get(command, command))
        if not installed and command in PIP_PACKAGES:
            installed = _pip_install(PIP_PACKAGES[command])
        if not shutil.which(command):
            missing.append(command)

    if missing:
        print(f"[!] Dependency installation failed: {', '.join(missing)}")
        sys.exit(1)
    return True


def ensure_python_packages(packages):
    missing = []
    for package in packages:
        if importlib.util.find_spec(package):
            continue
        print(f"[!] Missing Python package: {package}. Installing...")
        if not _pip_install(PIP_PACKAGES.get(package, package)) or not importlib.util.find_spec(package):
            missing.append(package)

    if missing:
        print(f"[!] Python dependency installation failed: {', '.join(missing)}")
        sys.exit(1)
    return True


def _first_existing(paths):
    for path in paths:
        if Path(path).is_file():
            return path
    return None


def _extract_rockyou():
    rockyou = Path("/usr/share/wordlists/rockyou.txt")
    gz_path = Path("/usr/share/wordlists/rockyou.txt.gz")
    if rockyou.is_file():
        return True
    if not gz_path.is_file():
        return False
    try:
        with gzip.open(gz_path, "rb") as src, rockyou.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        return rockyou.is_file()
    except PermissionError:
        prefix = _sudo_prefix()
        if not prefix:
            return False
        try:
            _run(prefix + ["gzip", "-dk", str(gz_path)])
            return rockyou.is_file()
        except subprocess.CalledProcessError:
            return False


def ensure_wordlists(names):
    resolved = {}
    needs_seclists = any(name.startswith("seclists_") for name in names)
    needs_wordlists = any(name in {"rockyou", "fasttrack"} for name in names)
    if needs_seclists and not any(_first_existing(WORDLISTS[name]) for name in names if name.startswith("seclists_")):
        print("[!] Missing dependency: seclists wordlists. Installing...")
        _apt_install("seclists")
    if needs_wordlists and not all(_first_existing(WORDLISTS[name]) for name in names if name in {"fasttrack"}):
        _apt_install("wordlists")
    if "rockyou" in names and not _first_existing(WORDLISTS["rockyou"]):
        print("[!] Missing dependency: rockyou.txt. Installing...")
        _apt_install("wordlists")
        _extract_rockyou()

    missing = []
    for name in names:
        path = _first_existing(WORDLISTS[name])
        if not path:
            missing.append(name)
        else:
            resolved[name] = path

    if missing:
        print(f"[!] Wordlist installation failed: {', '.join(missing)}")
        sys.exit(1)
    return resolved
