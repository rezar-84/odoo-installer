#!/usr/bin/env python3

import os
import sys
import subprocess
import platform

########################################
# HELPER FUNCTIONS
########################################

def print_ascii_banner():
    banner = r"""
   ____  ____          __
  / __ \/ __ \___  ___/ /
 / / / / /_/ / _ \/ _  / 
/ /_/ / _, _/  __/ __/  
\____/_/ |_|\___/_/     
   O D O O   W i z a r d

====================================
Welcome to the Odoo Setup & Management Tool
====================================
"""
    print(banner)

def check_root():
    """Check if the script is running as root."""
    if os.geteuid() != 0:
        print("\n[Error] You must run this script as root or with sudo.\n")
        sys.exit(1)

def detect_ubuntu():
    """Check if the OS is Ubuntu."""
    os_info = platform.platform().lower()
    if "ubuntu" not in os_info:
        print("\n[Warning] This script is designed for Ubuntu. Proceed with caution.")
    else:
        print("[OK] Ubuntu detected.")

def run_cmd(cmd, capture_output=False):
    """Helper to run shell commands."""
    print(f"\n[CMD] {cmd}")
    if capture_output:
        result = subprocess.run(cmd, shell=True, check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8'), result.stderr.decode('utf-8')
    else:
        subprocess.run(cmd, shell=True, check=False)

########################################
# PYTHON CHECK/INSTALL
########################################

def check_python_version():
    """
    Check if Python >= 3.11 is installed.
    Ask user if they want to install/upgrade to 3.11 or 3.12.
    """
    print("\n[Step] Checking Python version...")
    version_output, _ = run_cmd("python3 --version", capture_output=True)
    if version_output:
        parts = version_output.strip().split()
        if len(parts) == 2 and parts[0].lower() == "python":
            major, minor, *_ = parts[1].split(".")
            major = int(major)
            minor = int(minor)
            if (major == 3 and minor >= 11) or (major > 3):
                print(f"[OK] Detected Python {major}.{minor}. No upgrade needed.")
                return
            else:
                print(f"[Warning] Python {major}.{minor} is lower than 3.11.")
        else:
            print("[Warning] Unable to parse Python version.")
    else:
        print("[Warning] python3 not found or version is unknown.")

    print("""
We recommend Python 3.11 or 3.12 for Odoo.
1) Install/upgrade to Python 3.11
2) Install/upgrade to Python 3.12
3) Continue without upgrading (not recommended)
""")
    choice = input("Choose an option (1/2/3): ").strip()
    if choice == "1":
        run_cmd("apt update && apt install -y python3.11 python3.11-venv python3.11-dev")
        run_cmd("update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1")
    elif choice == "2":
        run_cmd("apt update && apt install -y software-properties-common")
        run_cmd("add-apt-repository ppa:deadsnakes/ppa -y")
        run_cmd("apt update && apt install -y python3.12 python3.12-venv python3.12-dev")
        run_cmd("update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1")
    else:
        print("[INFO] Continuing without upgrading Python...")

########################################
# INSTALL DEPENDENCIES
########################################

def prompt_install_dependencies():
    """
    Prompt user to install typical system dependencies for Odoo.
    """
    print("""
We need the following dependencies for Odoo:
- git, curl, wget, nano, build-essential
- PostgreSQL
- libpq-dev, libxml2-dev, libxslt1-dev, zlib1g-dev, etc.
- and possibly nginx for reverse proxy

Install dependencies now?
1) Yes
2) No
""")
    choice = input("Choose an option (1/2): ").strip()
    if choice == "1":
        deps = [
            "git", "curl", "wget", "nano", "build-essential", "python3-pip",
            "libpq-dev", "libxml2-dev", "libxslt1-dev", "zlib1g-dev", "libjpeg-dev",
            "postgresql", "postgresql-contrib", "nginx"
        ]
        run_cmd("apt update")
        run_cmd(f"apt install -y {' '.join(deps)}")

########################################
# DATABASE SETUP / CHECK
########################################

def db_exists(db_name):
    cmd = f"sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname='{db_name}';\""
    out, _ = run_cmd(cmd, capture_output=True)
    return out.strip() == "1"

def db_user_exists(db_user):
    cmd = f"sudo -u postgres psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='{db_user}';\""
    out, _ = run_cmd(cmd, capture_output=True)
    return out.strip() == "1"

def configure_database(state):
    """
    Configure or update database info.  
    Stores db_name, db_user, db_pass into the state dict.
    """
    print("""
PostgreSQL Database Configuration
---------------------------------
1) Create/Reuse DB & User
2) Return to Main Menu
""")
    choice = input("Choose an option (1/2): ").strip()
    if choice != "1":
        return

    db_name = input("Enter DB name (default: odoo18db): ").strip()
    if not db_name:
        db_name = "odoo18db"

    db_user = input("Enter DB user (default: odoo): ").strip()
    if not db_user:
        db_user = "odoo"

    db_pass = input("Enter DB password (default: odoo): ").strip()
    if not db_pass:
        db_pass = "odoo"

    # Ensure Postgres is running
    run_cmd("systemctl enable postgresql && systemctl start postgresql")

    # Check if user already exists
    if db_user_exists(db_user):
        print(f"[INFO] DB user '{db_user}' already exists.")
        reuse_user_choice = input("Do you want to reuse this user? (y/n): ").strip().lower()
        if reuse_user_choice == "n":
            run_cmd(f"sudo -u postgres psql -c \"DROP ROLE {db_user};\"")
            run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
            print(f"[OK] Re-created user '{db_user}' with new password.")
        else:
            # Update password if needed
            run_cmd(f"sudo -u postgres psql -c \"ALTER USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
            print(f"[OK] User '{db_user}' reused, password updated.")
    else:
        run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
        print(f"[OK] User '{db_user}' created.")

    # Check if DB already exists
    if db_exists(db_name):
        print(f"[INFO] Database '{db_name}' already exists.")
        reuse_db_choice = input("Do you want to reuse this database? (y/n): ").strip().lower()
        if reuse_db_choice == "n":
            run_cmd(f"sudo -u postgres psql -c \"DROP DATABASE {db_name};\"")
            run_cmd(f"sudo -u postgres psql -c \"CREATE DATABASE {db_name} OWNER {db_user};\"")
            print(f"[OK] Re-created database '{db_name}'.")
        else:
            print(f"[OK] Database '{db_name}' reused.")
    else:
        run_cmd(f"sudo -u postgres psql -c \"CREATE DATABASE {db_name} OWNER {db_user};\"")
        print(f"[OK] Database '{db_name}' created, owned by '{db_user}'.")

    # Store in state
    state['db_name'] = db_name
    state['db_user'] = db_user
    state['db_pass'] = db_pass
    print("[INFO] Database info updated in script state.")

########################################
# SYSTEM USER, ODOO SETUP
########################################

def system_user_exists(user_name):
    cmd = f"id -u {user_name}"
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc.returncode == 0

def setup_odoo(state):
    """
    Prompt for Odoo version, install path, system user, venv, and clone or reuse code.
    """
    print("""
Odoo Setup:
-----------
""")
    odoo_ver = input(f"Which Odoo version? (default: {state.get('odoo_ver','18.0')}): ").strip()
    if not odoo_ver:
        odoo_ver = state.get('odoo_ver', '18.0')

    install_path = input(f"Install directory? (default: {state.get('install_path','/opt/odoo18')}): ").strip()
    if not install_path:
        install_path = state.get('install_path', '/opt/odoo18')

    odoo_user = input(f"System user for Odoo? (default: {state.get('odoo_user','odoo')}): ").strip()
    if not odoo_user:
        odoo_user = state.get('odoo_user', 'odoo')

    print("""
Do you want to use a Python virtual environment for Odoo?
1) Yes
2) No (system-wide)
""")
    venv_choice = input("Choose (1/2): ").strip()
    use_venv = (venv_choice == "1")

    # Save to state
    state['odoo_ver'] = odoo_ver
    state['install_path'] = install_path
    state['odoo_user'] = odoo_user
    state['use_venv'] = use_venv

    # Create or reuse system user
    if system_user_exists(odoo_user):
        print(f"[INFO] System user '{odoo_user}' already exists.")
        reuse_user_choice = input("Do you want to reuse this user? (y/n): ").strip().lower()
        if reuse_user_choice == 'n':
            run_cmd(f"userdel -r {odoo_user}")
            run_cmd(f"useradd -m -d {install_path} -U -r -s /bin/bash {odoo_user}")
            print(f"[OK] Re-created system user '{odoo_user}'.")
        else:
            print(f"[OK] Reusing existing user '{odoo_user}'.")
    else:
        run_cmd(f"useradd -m -d {install_path} -U -r -s /bin/bash {odoo_user}")
        print(f"[OK] Created system user '{odoo_user}'.")

    # Clone or reuse Odoo code
    if os.path.isdir(install_path) and os.path.isdir(os.path.join(install_path, ".git")):
        print(f"[INFO] Found existing Odoo installation at {install_path}.")
        reuse_odoo_choice = input("Do you want to reuse this Odoo directory? (y/n): ").strip().lower()
        if reuse_odoo_choice == 'n':
            run_cmd(f"rm -rf {install_path}")
            run_cmd(f"git clone --depth 1 --branch {odoo_ver} https://github.com/odoo/odoo.git {install_path}")
            print(f"[OK] Downloaded fresh Odoo {odoo_ver} to {install_path}")
        else:
            print("[OK] Reusing existing Odoo directory.")
    else:
        run_cmd(f"git clone --depth 1 --branch {odoo_ver} https://github.com/odoo/odoo.git {install_path}")
        print(f"[OK] Downloaded Odoo {odoo_ver} to {install_path}")

    # Adjust ownership
    run_cmd(f"chown -R {odoo_user}:{odoo_user} {install_path}")

    # Set up venv or system-wide
    if use_venv:
        venv_path = os.path.join(install_path, "venv")
        if os.path.isdir(venv_path):
            print("[INFO] Virtual environment already exists.")
            reuse_venv_choice = input("Reuse existing venv? (y/n): ").strip().lower()
            if reuse_venv_choice == 'n':
                run_cmd(f"rm -rf {venv_path}")
                run_cmd(f"python3 -m venv {venv_path}")
        else:
            run_cmd(f"python3 -m venv {venv_path}")

        run_cmd(f"source {venv_path}/bin/activate && pip install --upgrade pip && pip install -r {install_path}/requirements.txt && deactivate")
        print("[OK] Odoo requirements installed in venv.")
    else:
        run_cmd(f"pip install --upgrade pip && pip install -r {install_path}/requirements.txt")
        print("[OK] Odoo requirements installed system-wide.")

def configure_odoo(state):
    """
    Prompt for Odoo config (master password, workers, etc.), then write to /etc/odoo.conf.
    """
    print("""
Odoo Configuration
------------------
""")
    admin_passwd = input("Master (admin) password for Odoo? (default: admin): ").strip()
    if not admin_passwd:
        admin_passwd = "admin"

    db_host = "False"
    db_port = "False"

    # If user previously configured DB in state
    db_name = state.get('db_name')
    db_user = state.get('db_user')
    db_pass = state.get('db_pass')

    if db_name:
        # We'll assume local
        db_host = "localhost"
        db_port = "5432"
    else:
        # Possibly user wants remote DB or skip
        db_host_input = input("DB Host? (default: False for local socket): ").strip()
        if db_host_input:
            db_host = db_host_input
        db_port_input = input("DB Port? (default: False): ").strip()
        if db_port_input:
            db_port = db_port_input

        if not db_user:
            db_user = "odoo"
        if not db_pass:
            db_pass = "False"

    workers = input("Number of worker processes? (default: 2): ").strip() or "2"

    install_path = state.get('install_path', '/opt/odoo18')

    # Write config
    conf_path = "/etc/odoo.conf"
    content = f"""[options]
; Odoo Configuration File
admin_passwd = {admin_passwd}
db_host = {db_host}
db_port = {db_port}
db_user = {db_user}
db_password = {db_pass}
addons_path = {install_path}/addons
logfile = /var/log/odoo/odoo.log
workers = {workers}
"""

    with open(conf_path, 'w') as f:
        f.write(content)

    run_cmd(f"mkdir -p /var/log/odoo && chown -R {state.get('odoo_user','odoo')} /var/log/odoo")
    run_cmd(f"chown root:root {conf_path} && chmod 640 {conf_path}")

    print(f"[OK] Wrote Odoo configuration to {conf_path}")
    # Save to state
    state['admin_passwd'] = admin_passwd
    state['workers'] = workers
    state['odoo_conf_path'] = conf_path
    print("[INFO] Odoo configuration updated in script state.")

########################################
# SERVICE
########################################

def create_odoo_service(state):
    """
    Create or overwrite systemd service for Odoo.
    """
    install_path = state.get('install_path', '/opt/odoo18')
    odoo_user = state.get('odoo_user', 'odoo')
    service_file = "/etc/systemd/system/odoo.service"

    exec_path = f"{install_path}/odoo-bin"
    if state.get('use_venv'):
        exec_path = f"{install_path}/venv/bin/python3 {install_path}/odoo-bin"

    service_content = f"""[Unit]
Description=Odoo Service
After=network.target postgresql.service

[Service]
Type=simple
User={odoo_user}
Group={odoo_user}
ExecStart={exec_path} --config=/etc/odoo.conf
Restart=always

[Install]
WantedBy=multi-user.target
"""
    with open(service_file, 'w') as f:
        f.write(service_content)

    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable --now odoo.service")
    print("[OK] Odoo service started or restarted.")
    state['service_file'] = service_file

########################################
# CLOUDFLARE / ACME
########################################

def prompt_cloudflare(state):
    """
    Prompt user for Cloudflare integration details, store in state.
    """
    print("""
Cloudflare Integration
----------------------
We can use acme.sh with Cloudflare DNS API to issue Let's Encrypt certificates automatically.
""")
    choice = input("Do you want to configure Cloudflare SSL? (y/n): ").strip().lower()
    if choice != 'y':
        print("[INFO] Skipping Cloudflare integration.")
        return

    api_token = input("Enter your Cloudflare API Token: ").strip()
    domain = input("Enter your domain (e.g. example.com): ").strip()
    subdomain = input("Subdomain? (leave empty if root domain): ").strip()

    state['cloudflare'] = {
        'api_token': api_token,
        'domain': domain,
        'subdomain': subdomain
    }
    print("[INFO] Cloudflare info stored. Use 'Issue/Install SSL' from the menu to proceed.")

def setup_cloudflare_ssl(state):
    """
    Use acme.sh + DNS-01 challenge with CF token for SSL.
    """
    if 'cloudflare' not in state or not state['cloudflare'].get('api_token'):
        print("[Error] Cloudflare not configured. Go to 'Configure Domain/Cloudflare' first.")
        return

    api_token = state['cloudflare']['api_token']
    domain = state['cloudflare']['domain']
    subdomain = state['cloudflare']['subdomain']
    if not domain:
        print("[Error] Domain is missing. Please re-enter Cloudflare info.")
        return

    # Install acme.sh if not present
    print("\n[INFO] Installing acme.sh (if not installed)...")
    run_cmd("apt install -y socat")
    run_cmd("curl https://get.acme.sh | sh -s email=my@example.com")

    os.environ["CF_Token"] = api_token

    full_domain = f"{subdomain}.{domain}" if subdomain else domain
    print(f"[INFO] Issuing certificate for {full_domain} via acme.sh (DNS-01 challenge)...")

    acme_cmd = f"~/.acme.sh/acme.sh --issue --dns dns_cf -d {full_domain}"
    run_cmd(acme_cmd)

    # Install the certificate to /etc/letsencrypt/odoo:
    run_cmd("mkdir -p /etc/letsencrypt/")
    install_cmd = (f"~/.acme.sh/acme.sh --install-cert -d {full_domain} "
                   f"--key-file /etc/letsencrypt/odoo.key "
                   f"--fullchain-file /etc/letsencrypt/odoo.crt "
                   f"--reloadcmd \"systemctl reload nginx\"")
    run_cmd(install_cmd)

    print(f"[OK] SSL certificate installed for {full_domain} in /etc/letsencrypt.")

########################################
# NGINX CONFIG
########################################

def configure_nginx(state):
    """
    Configure or update an Nginx reverse proxy for Odoo with SSL.
    """
    print("""
Nginx Reverse Proxy Setup
-------------------------
""")
    choice = input("Do you want to configure Nginx now? (y/n): ").strip().lower()
    if choice != 'y':
        print("[INFO] Skipping Nginx configuration.")
        return

    if 'cloudflare' not in state:
        domain = input("Enter domain name (e.g. odoo.example.com): ").strip()
    else:
        domain = state['cloudflare']['domain']
        subdomain = state['cloudflare']['subdomain']
        domain = f"{subdomain}.{domain}" if subdomain else domain

    if not domain or domain == ".":
        print("[Error] Invalid domain.")
        return

    config_path = "/etc/nginx/sites-available/odoo"
    conf_content = f"""
server {{
    listen 80;
    server_name {domain};

    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {domain};

    ssl_certificate /etc/letsencrypt/odoo.crt;
    ssl_certificate_key /etc/letsencrypt/odoo.key;

    # Proxy buffers
    proxy_buffers 16 64k;
    proxy_buffer_size 128k;

    location / {{
        proxy_pass http://127.0.0.1:8069;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}

    location /longpolling {{
        proxy_pass http://127.0.0.1:8072;
    }}

    # Gzip
    gzip on;
    gzip_min_length 1000;
    gzip_types text/plain application/xml application/json text/css application/javascript;
}}
"""
    with open(config_path, 'w') as f:
        f.write(conf_content)

    run_cmd(f"ln -sf {config_path} /etc/nginx/sites-enabled/odoo")
    run_cmd("systemctl restart nginx")
    print(f"[OK] Nginx reverse proxy configured for {domain}.")

########################################
# SSH HARDENING
########################################

def harden_ssh():
    print("""
SSH Hardening
-------------
""")
    choice = input("Do you want to harden SSH? (y/n): ").strip().lower()
    if choice != 'y':
        return

    pub_key = input("Paste your public SSH key (e.g. ssh-rsa AAAAB3...):\n").strip()
    if not pub_key.startswith("ssh-"):
        print("[Warning] That doesn't look like a valid SSH key. Skipping.")
        return

    ssh_user = input("Which user do you want to add the key for? (default: root): ").strip()
    if not ssh_user:
        ssh_user = "root"

    user_home = f"/home/{ssh_user}" if ssh_user != "root" else "/root"
    ssh_dir = os.path.join(user_home, ".ssh")
    run_cmd(f"mkdir -p {ssh_dir}")
    auth_keys_path = os.path.join(ssh_dir, "authorized_keys")

    with open(auth_keys_path, 'a') as f:
        f.write(pub_key + "\n")

    run_cmd(f"chown -R {ssh_user}:{ssh_user} {ssh_dir}")
    run_cmd(f"chmod 700 {ssh_dir}")
    run_cmd(f"chmod 600 {auth_keys_path}")

    disable_choice = input("Disable password login? (y/n): ").strip().lower()
    if disable_choice == 'y':
        sshd_config = "/etc/ssh/sshd_config"
        with open(sshd_config, 'r') as f:
            lines = f.readlines()
        new_lines = []
        for line in lines:
            if line.strip().startswith("PasswordAuthentication"):
                new_lines.append("PasswordAuthentication no\n")
            else:
                new_lines.append(line)
        with open(sshd_config, 'w') as f:
            f.write("".join(new_lines))
        run_cmd("systemctl restart sshd")
        print("[OK] Password login disabled. Make sure your SSH key works!")

########################################
# FIREWALL (UFW) SETUP
########################################

def configure_firewall():
    print("""
UFW Firewall Configuration
--------------------------
We'll open ports 22 (SSH), 80 (HTTP), 443 (HTTPS), and 8069 for Odoo (optionally).
""")
    choice = input("Do you want to install and configure UFW? (y/n): ").strip().lower()
    if choice != 'y':
        return

    run_cmd("apt install -y ufw")

    # Basic rules
    run_cmd("ufw allow 22")
    run_cmd("ufw allow 80")
    run_cmd("ufw allow 443")

    # Option to open Odoo port directly
    odoo_port_choice = input("Open Odoo port 8069? (y/n): ").strip().lower()
    if odoo_port_choice == 'y':
        run_cmd("ufw allow 8069")

    run_cmd("ufw enable")
    run_cmd("ufw status")
    print("[OK] UFW firewall configured.")

########################################
# FULL WIZARD
########################################

def run_full_wizard(state):
    """
    Run all steps in sequence.
    """
    check_python_version()
    prompt_install_dependencies()
    configure_database(state)
    setup_odoo(state)
    configure_odoo(state)
    create_odoo_service(state)
    prompt_cloudflare(state)  # Just collects info
    setup_cloudflare_ssl(state)
    configure_nginx(state)
    harden_ssh()
    configure_firewall()
    print("\n[Installation Complete]")
    print("=========================================")
    print("Odoo should now be running on port 8069. If you configured")
    print("Nginx and SSL, then your domain should serve Odoo over HTTPS.")
    print("=========================================")

########################################
# MAIN MENU
########################################

def main_menu(state):
    while True:
        print("""
=================================
 Main Menu
=================================
1) Run Complete Setup Wizard
2) Database Setup/Update
3) Odoo Setup/Update
4) Configure Odoo (Config File)
5) Create/Update Odoo Service
6) Configure Domain / Cloudflare
7) Issue/Install SSL Certificate
8) Configure Nginx Reverse Proxy
9) SSH Hardening
10) Configure Firewall
11) Exit
""")
        choice = input("Select an option: ").strip()
        if choice == "1":
            run_full_wizard(state)
        elif choice == "2":
            configure_database(state)
        elif choice == "3":
            setup_odoo(state)
        elif choice == "4":
            configure_odoo(state)
        elif choice == "5":
            create_odoo_service(state)
        elif choice == "6":
            prompt_cloudflare(state)
        elif choice == "7":
            setup_cloudflare_ssl(state)
        elif choice == "8":
            configure_nginx(state)
        elif choice == "9":
            harden_ssh()
        elif choice == "10":
            configure_firewall()
        elif choice == "11":
            print("[INFO] Exiting.")
            break
        else:
            print("[Warning] Invalid choice. Please select again.")

def main():
    print_ascii_banner()
    check_root()
    detect_ubuntu()

    # We store dynamic states here, e.g. db info, domain, etc.
    state = {}

    main_menu(state)
    print("\n[Done] Thanks for using the Odoo Setup & Management Tool!\n")

if __name__ == "__main__":
    main()

