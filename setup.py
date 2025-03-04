#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import platform
import re
import time

STATE_FILE = "/etc/odoo_install_state.json"
LOG_FILE = "/var/log/odoo_install.log"

########################################
# Logging Functions
########################################

def log(msg):
    """Append a message to the log file and print to console."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}\n"
    print(line.strip())
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line)
    except IOError:
        print(f"[WARN] Could not write to log file {LOG_FILE}.")

def run_cmd(cmd, capture_output=False):
    """
    Helper to run shell commands, logs them, prints output if errors occur.
    Returns (stdout, stderr, return_code).
    """
    log(f"RUN CMD: {cmd}")
    if capture_output:
        result = subprocess.run(cmd, shell=True, check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        if result.returncode != 0:
            log(f"[ERROR] Command failed with code {result.returncode}")
            log(f"STDERR: {stderr}")
        return (stdout, stderr, result.returncode)
    else:
        result = subprocess.run(cmd, shell=True, check=False)
        if result.returncode != 0:
            log(f"[ERROR] Command '{cmd}' failed with code {result.returncode}")
        return ("", "", result.returncode)

########################################
# State Persistence
########################################

def load_state():
    """Load non-sensitive state from /etc/odoo_install_state.json, if present."""
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict):
                log("[INFO] Loaded existing install state.")
                return data
        except Exception as e:
            log(f"[WARN] Could not parse state file: {e}")
    return {}

def save_state(state):
    """Save non-sensitive data to /etc/odoo_install_state.json."""
    state_copy = dict(state)
    # Remove any known password fields
    state_copy.pop('db_pass', None)
    state_copy.pop('api_token', None)
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state_copy, f, indent=2)
        log("[INFO] Saved state (excluding passwords).")
    except Exception as e:
        log(f"[WARN] Could not save state: {e}")

########################################
# Root / OS checks
########################################

def check_root():
    if os.geteuid() != 0:
        log("[ERROR] You must run this script as root or with sudo.")
        sys.exit(1)

def detect_ubuntu():
    os_info = platform.platform().lower()
    if "ubuntu" not in os_info:
        log("[WARN] This script is designed for Ubuntu 24.04. Proceed with caution.")
    else:
        log("[OK] Ubuntu detected.")

########################################
# Utility
########################################

def user_exists(user_name):
    cmd = f"id -u {user_name}"
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc.returncode == 0

def ensure_dir(d):
    if not os.path.isdir(d):
        try:
            os.makedirs(d)
            log(f"[INFO] Created directory {d}.")
        except Exception as e:
            log(f"[ERROR] Could not create directory {d}: {e}")

########################################
# APT / Fix-Broken Helpers
########################################

def apt_install(pkg_list):
    """
    Attempt 'apt install -y <pkg_list>'.
    If it fails, prompt to run 'apt --fix-broken install', then re-attempt.
    Returns True if final install is successful, False otherwise.
    """
    stdout, stderr, rc = run_cmd(f"apt install -y {pkg_list}", capture_output=True)
    if rc == 0:
        return True

    # If we got here, apt failed
    log("[ERROR] apt install failed. Attempt fix-broken approach?")
    fix_choice = input("Attempt 'apt --fix-broken install'? (y/n): ").strip().lower()
    if fix_choice == 'y':
        _, _, rc2 = run_cmd("apt --fix-broken install -y", capture_output=True)
        if rc2 == 0:
            # re-attempt
            _, _, rc3 = run_cmd(f"apt install -y {pkg_list}", capture_output=True)
            if rc3 == 0:
                return True
            else:
                log(f"[ERROR] apt install of {pkg_list} still failed after fix-broken.")
                return False
        else:
            log("[ERROR] fix-broken also failed.")
            return False
    else:
        log("[WARN] Skipping fix-broken. apt install remains failed.")
        return False

########################################
# Steps
########################################

def check_python_version():
    log("Checking Python version (>=3.11 recommended).")
    stdout, stderr, rc = run_cmd("python3 --version", capture_output=True)
    if stdout:
        parts = stdout.strip().split()
        if len(parts) == 2 and parts[0].lower() == "python":
            try:
                maj, min = parts[1].split(".")[:2]
                maj = int(maj)
                min = int(min)
                if (maj == 3 and min >= 11) or (maj > 3):
                    log(f"[OK] Detected Python {maj}.{min}.")
                    return
                else:
                    log(f"[WARN] Python {maj}.{min} is lower than 3.11.")
            except:
                log("[WARN] Unable to parse Python version properly.")
        else:
            log("[WARN] python3 version output unrecognized.")
    else:
        log("[WARN] python3 not found or version unknown.")

def prompt_install_dependencies():
    log("Prompting user to install system dependencies.")
    print("""
We'll install required packages for Odoo 18 on Ubuntu 24.04, including:
- git, curl, wget, nano, build-essential
- PostgreSQL and dev libs
- libpq-dev, libxml2-dev, libxslt1-dev, zlib1g-dev, libjpeg-dev
- nginx, xfonts-75dpi, xfonts-base
- nodejs, npm, yarn
- wkhtmltopdf

Install dependencies now?
1) Yes
2) No
""")
    choice = input("Choose (1/2): ").strip()
    if choice != "1":
        log("[INFO] Skipping dependency installation.")
        return

    base_deps = (
        "git curl wget nano build-essential python3-pip "
        "libpq-dev libxml2-dev libxslt1-dev zlib1g-dev libjpeg-dev "
        "postgresql postgresql-contrib nginx xfonts-75dpi xfonts-base wkhtmltopdf"
    )

    # Attempt main packages
    ok = apt_install(base_deps)
    if not ok:
        log("[ERROR] Base dependencies failed to install. Aborting or skipping further steps.")
        return

    # NodeSource script
    # If it fails, no sense continuing with nodejs
    stdout, stderr, rc = run_cmd("curl -sL https://deb.nodesource.com/setup_18.x | bash -", capture_output=True)
    if rc != 0:
        log("[ERROR] NodeSource setup script failed. Node.js won't install. Aborting node steps.")
        return

    # nodejs + npm
    ok = apt_install("nodejs npm")
    if not ok:
        log("[ERROR] nodejs/npm installation failed. Aborting node steps.")
        return

    # Yarn
    stdout, stderr, rc = run_cmd("npm install -g yarn", capture_output=True)
    if rc != 0:
        log("[ERROR] Yarn installation failed. Some Odoo assets might not build.")
        return

    log("[OK] Dependencies installed (with potential warnings if partial failures).")

########################################
# Database, Odoo, and so on remain the same...
########################################

def configure_database(state):
    # same as in final script above
    ...
    # omitted for brevity

def setup_odoo(state):
    # same as in final script
    ...
    # omitted for brevity

def clone_odoo(odoo_ver, install_path):
    # same as in final script
    ...
    # omitted for brevity

def create_venv(path):
    # same as in final script
    ...
    # omitted for brevity

def install_requirements_venv(install_path, venv_path):
    # same as in final script
    ...
    # omitted for brevity

def install_requirements_system(install_path):
    # same as in final script
    ...
    # omitted for brevity

def prompt_odoo_memory_config(state):
    # same as in final script
    ...
    # omitted for brevity

def detect_system_memory_mb():
    # same as in final script
    ...
    # omitted for brevity

def advanced_postgres_tuning():
    # same as in final script
    ...
    # omitted for brevity

def configure_odoo(state):
    # same as in final script (now includes limits)
    ...
    # omitted for brevity

def create_odoo_service(state):
    # same as in final script
    ...
    # omitted for brevity

def prompt_cloudflare(state):
    # same as in final script
    ...
    # omitted for brevity

def setup_cloudflare_ssl(state):
    # same as in final script
    ...
    # omitted for brevity

def configure_nginx(state):
    # same as in final script
    ...
    # omitted for brevity

def harden_ssh():
    # same as in final script
    ...
    # omitted for brevity

def configure_firewall():
    # same as in final script
    ...
    # omitted for brevity

def run_full_wizard(state):
    log("Running full wizard.")
    check_python_version()
    prompt_install_dependencies()
    configure_database(state)
    setup_odoo(state)
    prompt_odoo_memory_config(state)
    configure_odoo(state)
    create_odoo_service(state)
    prompt_cloudflare(state)
    setup_cloudflare_ssl(state)
    configure_nginx(state)
    harden_ssh()
    configure_firewall()
    log("[INSTALLATION COMPLETE] Odoo 18 is presumably running on port 8069 with Nginx SSL if configured.")
    print("\n[Installation Complete]\n")

def main_menu(state):
    while True:
        save_state(state)
        print("""
==================================
 Odoo 18 Installation Main Menu
==================================
1) Full Odoo 18 Installation Wizard
2) Install Dependencies
3) Configure PostgreSQL DB
4) Setup/Update Odoo (Clone & Venv)
5) Memory Worker Config for Odoo
6) Configure Odoo (Write /etc/odoo.conf)
7) Create Odoo systemd service
8) Cloudflare Domain/SSL Setup
9) Issue/Install SSL Certificate (acme.sh)
10) Configure Nginx Reverse Proxy
11) SSH Hardening
12) Firewall Setup
13) Advanced PostgreSQL Tuning
14) Exit
""")
        choice = input("Select an option: ").strip()
        if choice == "1":
            run_full_wizard(state)
        elif choice == "2":
            prompt_install_dependencies()
        elif choice == "3":
            configure_database(state)
        elif choice == "4":
            setup_odoo(state)
        elif choice == "5":
            prompt_odoo_memory_config(state)
        elif choice == "6":
            configure_odoo(state)
        elif choice == "7":
            create_odoo_service(state)
        elif choice == "8":
            prompt_cloudflare(state)
        elif choice == "9":
            setup_cloudflare_ssl(state)
        elif choice == "10":
            configure_nginx(state)
        elif choice == "11":
            harden_ssh()
        elif choice == "12":
            configure_firewall()
        elif choice == "13":
            advanced_postgres_tuning()
        elif choice == "14":
            log("[INFO] Exiting script.")
            break
        else:
            print("[WARN] Invalid choice. Please select again.")

def main():
    ensure_dir(os.path.dirname(LOG_FILE))
    check_root()
    detect_ubuntu()

    state = load_state()
    main_menu(state)
    save_state(state)
    print("\n[Done] Odoo 18 Setup Script Exiting.\n")

if __name__ == "__main__":
    main()

