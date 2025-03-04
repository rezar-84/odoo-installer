#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
import re

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
Welcome to the Odoo 18 Installer for Ubuntu 24.04
====================================
"""
    print(banner)

def check_root():
    """Check if the script is running as root."""
    if os.geteuid() != 0:
        print("\n[Error] You must run this script as root or with sudo.\n")
        sys.exit(1)

def detect_ubuntu():
    """Check if the OS is Ubuntu 24.04."""
    os_info = platform.platform().lower()
    if "ubuntu" not in os_info:
        print("\n[Warning] This script is designed for Ubuntu 24.04. Proceed with caution.")
    else:
        print("[OK] Ubuntu detected.")

def run_cmd(cmd, capture_output=False):
    """Helper to run shell commands, printing them first."""
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
We recommend Python 3.11 or 3.12 for Odoo 18.
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
# INSTALL CORE DEPENDENCIES
########################################

def prompt_install_dependencies():
    """
    Prompt user to install typical system dependencies for Odoo 18,
    including Node.js, yarn, wkhtmltopdf, etc.
    """
    print("""
We'll install required packages for Odoo 18 on Ubuntu 24.04, including:
- git, curl, wget, nano, build-essential
- PostgreSQL and dev libs
- libpq-dev, libxml2-dev, libxslt1-dev, zlib1g-dev, libjpeg-dev
- nginx for reverse proxy
- nodejs, npm, yarn (for Odoo assets)
- wkhtmltopdf (for printing PDFs)
Install dependencies now?
1) Yes
2) No
""")
    choice = input("Choose an option (1/2): ").strip()
    if choice == "1":
        # Basic system deps
        base_deps = [
            "git", "curl", "wget", "nano", "build-essential", "python3-pip",
            "libpq-dev", "libxml2-dev", "libxslt1-dev", "zlib1g-dev", "libjpeg-dev",
            "postgresql", "postgresql-contrib", "nginx", "xfonts-75dpi", "xfonts-base"
        ]
        run_cmd("apt update")
        run_cmd(f"apt install -y {' '.join(base_deps)}")

        # Node.js, Yarn, wkhtmltopdf
        print("[INFO] Installing Node.js, npm, yarn, wkhtmltopdf...")
        # For Node 16/18/20, you might prefer official NodeSource, e.g.:
        run_cmd("curl -sL https://deb.nodesource.com/setup_18.x | bash -")
        run_cmd("apt install -y nodejs npm")

        # Yarn
        run_cmd("npm install -g yarn")

        # Wkhtmltopdf (the older 0.12.5 is usually recommended, but let's do standard apt for now)
        run_cmd("apt install -y wkhtmltopdf")

        print("[OK] Dependencies installed.")

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
        if reuse_user_choice == 'n':
            run_cmd(f"sudo -u postgres psql -c \"DROP ROLE {db_user};\"")
            run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
            print(f"[OK] Re-created user '{db_user}' with new password.")
        else:
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
    Prompt for Odoo version, install path, system user, venv, clone or reuse code.
    Actually clones Odoo from github and installs requirements.
    """
    print("""
Odoo Setup:
-----------
""")
    # Default to 18.0
    default_version = state.get('odoo_ver', '18.0')
    odoo_ver = input(f"Which Odoo version? (default: {default_version}): ").strip()
    if not odoo_ver:
        odoo_ver = default_version

    default_path = state.get('install_path', '/opt/odoo18')
    install_path = input(f"Install directory? (default: {default_path}): ").strip()
    if not install_path:
        install_path = default_path

    default_user = state.get('odoo_user', 'odoo')
    odoo_user = input(f"System user for Odoo? (default: {default_user}): ").strip()
    if not odoo_user:
        odoo_user = default_user

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

########################################
# MEMORY CONFIG FOR ODOO WORKERS
########################################

def detect_system_memory_mb():
    """Read /proc/meminfo to get total system memory in MB."""
    try:
        with open("/proc/meminfo") as f:
            data = f.read()
        match = re.search(r"^MemTotal:\s+(\d+)\skB", data, re.MULTILINE)
        if match:
            mem_kb = int(match.group(1))
            return mem_kb // 1024
    except:
        pass
    return 0

def prompt_odoo_memory_config(state):
    """
    Ask for memory-based tuning for the number of Odoo worker processes.
    We do NOT do PostgreSQL tuning here (that is in a separate menu item).
    """
    print("""
Odoo Memory Configuration (Workers)
-----------------------------------
We can suggest an appropriate number of Odoo worker processes based on your server RAM.
""")
    sys_mem = detect_system_memory_mb()
    if sys_mem > 0:
        print(f"[INFO] Detected ~{sys_mem} MB system memory.")
    else:
        print("[WARNING] Could not detect system memory from /proc/meminfo.")

    choice = input("Do you want to set workers based on memory? (y/n): ").strip().lower()
    if choice != 'y':
        return

    # Basic heuristic
    default_workers = 2
    if sys_mem >= 2048 and sys_mem < 4096:
        default_workers = 2
    elif sys_mem >= 4096 and sys_mem < 8192:
        default_workers = 4
    elif sys_mem >= 8192 and sys_mem < 16384:
        default_workers = 6
    elif sys_mem >= 16384:
        default_workers = 8

    prompt_text = f"Number of Odoo worker processes? (default: {default_workers}): "
    workers_in = input(prompt_text).strip()
    if not workers_in:
        workers_in = str(default_workers)
    state['workers'] = workers_in
    print(f"[OK] Worker count set to {workers_in}. Remember to update your Odoo config if needed.")

########################################
# ADVANCED POSTGRES TUNING
########################################

def advanced_postgres_tuning():
    """
    Move advanced PG memory tuning to a separate menu item, as requested.
    """
    print("""
Advanced PostgreSQL Tuning
--------------------------
This will let you set shared_buffers, work_mem, and maintenance_work_mem.

Warning: Always ensure these values are correct for your hardware.
""")
    proceed = input("Do you want to proceed with advanced PG tuning? (y/n): ").strip().lower()
    if proceed != 'y':
        print("[INFO] Skipping advanced PG tuning.")
        return

    # Usually postgresql 16 in Ubuntu 24.04
    pg_conf = "/etc/postgresql/16/main/postgresql.conf"
    if not os.path.isfile(pg_conf):
        # fallback if 16 not found
        pg_conf = "/etc/postgresql/14/main/postgresql.conf"

    shared_buffers = input("shared_buffers? (e.g. 2GB) [Press enter to skip]: ").strip()
    work_mem = input("work_mem? (e.g. 16MB) [Press enter to skip]: ").strip()
    maintenance_work_mem = input("maintenance_work_mem? (e.g. 64MB) [Press enter to skip]: ").strip()

    run_cmd("systemctl stop postgresql")

    # We'll do naive replacements or appends
    with open(pg_conf, 'r') as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        # Comments won't get replaced automatically, but let's keep it simple
        if shared_buffers and line.strip().startswith("shared_buffers"):
            new_lines.append(f"shared_buffers = {shared_buffers}\n")
        elif work_mem and line.strip().startswith("work_mem"):
            new_lines.append(f"work_mem = {work_mem}\n")
        elif maintenance_work_mem and line.strip().startswith("maintenance_work_mem"):
            new_lines.append(f"maintenance_work_mem = {maintenance_work_mem}\n")
        else:
            new_lines.append(line)

    # If not found, we append lines at the end
    if shared_buffers and not any("shared_buffers" in l for l in new_lines):
        new_lines.append(f"\nshared_buffers = {shared_buffers}\n")
    if work_mem and not any("work_mem" in l for l in new_lines):
        new_lines.append(f"work_mem = {work_mem}\n")
    if maintenance_work_mem and not any("maintenance_work_mem" in l for l in new_lines):
        new_lines.append(f"maintenance_work_mem = {maintenance_work_mem}\n")

    with open(pg_conf, 'w') as f:
        f.write("".join(new_lines))

    run_cmd("systemctl start postgresql")
    print("[OK] PostgreSQL advanced tuning applied and service restarted.")

########################################
# CONFIGURE ODOO
########################################

def configure_odoo(state):
    """
    Prompt for Odoo config (master password, workers, etc.), then write /etc/odoo.conf.
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

    # If we have a memory-based workers setting in state, use that as a default
    default_workers = state.get('workers', '2')
    workers_in = input(f"Number of worker processes? (default: {default_workers}): ").strip()
    if not workers_in:
        workers_in = default_workers

    install_path = state.get('install_path', '/opt/odoo18')
    conf_path = "/etc/odoo.conf"
    content = f"""[options]
; Odoo 18 Configuration File
admin_passwd = {admin_passwd}
db_host = {db_host}
db_port = {db_port}
db_user = {db_user}
db_password = {db_pass}
addons_path = {install_path}/addons
logfile = /var/log/odoo/odoo.log
workers = {workers_in}
"""

    with open(conf_path, 'w') as f:
        f.write(content)

    odoo_user = state.get('odoo_user', 'odoo')
    run_cmd(f"mkdir -p /var/log/odoo && chown -R {odoo_user} /var/log/odoo")
    run_cmd(f"chown root:root {conf_path} && chmod 640 {conf_path}")

    print(f"[OK] Wrote Odoo configuration to {conf_path}")
    # Save to state
    state['admin_passwd'] = admin_passwd
    state['workers'] = workers_in
    state['odoo_conf_path'] = conf_path
    print("[INFO] Odoo configuration updated in script state.")

########################################
# CREATE ODOO SERVICE
########################################

def create_odoo_service(state):
    """
    Create or overwrite systemd service for Odoo 18.
    """
    install_path = state.get('install_path', '/opt/odoo18')
    odoo_user = state.get('odoo_user', 'odoo')
    service_file = "/etc/systemd/system/odoo.service"

    exec_path = f"{install_path}/odoo-bin"
    if state.get('use_venv'):
        exec_path = f"{install_path}/venv/bin/python3 {install_path}/odoo-bin"

    service_content = f"""[Unit]
Description=Odoo 18 Service
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
    print("[INFO] Cloudflare info stored. Use 'Issue/Install SSL Certificate' from the menu to proceed.")

def setup_cloudflare_ssl(state):
    """
    Use acme.sh + DNS-01 challenge with CF token for SSL.
    """
    if 'cloudflare' not in state or not state['cloudflare'].get('api_token'):
        print("[Error] Cloudflare not configured. Go to 'Configure Domain / Cloudflare' first.")
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

    domain = ""
    if 'cloudflare' in state:
        domain_part = state['cloudflare']['domain']
        subdomain_part = state['cloudflare']['subdomain']
        domain = f"{subdomain_part}.{domain_part}" if subdomain_part else domain_part

    if not domain:
        domain = input("Enter domain name (e.g. odoo.example.com): ").strip()

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
We'll open ports 22 (SSH), 80 (HTTP), 443 (HTTPS), and optionally 8069 for Odoo direct access.
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
    Run all steps in a typical sequence:
    1. Check/upgrade Python
    2. Install dependencies (including Node.js/wkhtmltopdf)
    3. Configure DB
    4. Clone and install Odoo 18
    5. Memory config for Odoo workers
    6. Configure Odoo
    7. Create systemd service
    8. Prompt for CF SSL
    9. Issue CF SSL
    10. Configure Nginx
    11. SSH Hardening
    12. Firewall
    """
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

    print("\n[Installation Complete]")
    print("=========================================")
    print("Odoo 18 should now be running on port 8069. If you configured")
    print("Nginx and SSL, your domain should serve Odoo over HTTPS.")
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
1) Full Odoo 18 Installation (Wizard)
2) Install Dependencies (Nodejs, Wkhtml, etc.)
3) Database Setup/Update
4) Odoo Setup/Update (Clone & Python deps)
5) Odoo Memory Config (Workers)
6) Configure Odoo (Write /etc/odoo.conf)
7) Create/Update Odoo Systemd Service
8) Configure Domain / Cloudflare
9) Issue/Install SSL Certificate
10) Configure Nginx Reverse Proxy
11) SSH Hardening
12) Configure Firewall
13) Advanced PostgreSQL Tuning (Separate)
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
            print("[INFO] Exiting.")
            break
        else:
            print("[Warning] Invalid choice. Please select again.")

def main():
    print_ascii_banner()
    check_root()
    detect_ubuntu()

    # We store dynamic states here, e.g. DB info, domain, memory settings, etc.
    state = {}

    main_menu(state)
    print("\n[Done] Thanks for using the Odoo 18 Setup & Ma

