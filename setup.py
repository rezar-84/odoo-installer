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
    """Helper to run shell commands, logs them, prints output if errors occur."""
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
        return (None, None, result.returncode)

########################################
# State Persistence
########################################

def load_state():
    """Load non-sensitive state from /etc/odoo_install_state.json, if present."""
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                data = json.load(f)
            # Make sure it's a dict
            if isinstance(data, dict):
                log("[INFO] Loaded existing install state.")
                return data
        except Exception as e:
            log(f"[WARN] Could not parse state file: {e}")
    return {}

def save_state(state):
    """Save non-sensitive data to /etc/odoo_install_state.json."""
    # We do NOT store passwords for safety
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
# Steps
########################################

def check_python_version():
    log("Checking Python version (>=3.11 recommended).")
    stdout, stderr, rc = run_cmd("python3 --version", capture_output=True)
    if stdout:
        parts = stdout.strip().split()
        if len(parts) == 2 and parts[0].lower() == "python":
            maj, min, *_ = parts[1].split(".")
            try:
                maj = int(maj)
                min = int(min)
                if (maj == 3 and min >= 11) or (maj > 3):
                    log(f"[OK] Detected Python {maj}.{min}.")
                    return
                else:
                    log(f"[WARN] Python {maj}.{min} is lower than 3.11.")
            except:
                pass
        else:
            log("[WARN] Unable to parse Python version.")
    else:
        log("[WARN] python3 not found or version unknown.")

    log("""We recommend Python 3.11 or 3.12 for Odoo 18.
Please install or upgrade manually if needed, or proceed if you have custom setup.
""")

def prompt_install_dependencies():
    log("Prompting user to install system dependencies.")
    print("""
We'll install required packages for Odoo 18 on Ubuntu 24.04, including:
- git, curl, wget, nano, build-essential
- PostgreSQL and dev libs
- libpq-dev, libxml2-dev, libxslt1-dev, zlib1g-dev, libjpeg-dev
- nginx for reverse proxy
- nodejs, npm, yarn (for Odoo assets)
- wkhtmltopdf (for PDF reports)

Install dependencies now?
1) Yes
2) No
""")
    choice = input("Choose (1/2): ").strip()
    if choice == "1":
        deps = [
            "git", "curl", "wget", "nano", "build-essential", "python3-pip",
            "libpq-dev", "libxml2-dev", "libxslt1-dev", "zlib1g-dev", "libjpeg-dev",
            "postgresql", "postgresql-contrib", "nginx", "xfonts-75dpi", "xfonts-base",
            "wkhtmltopdf"
        ]
        run_cmd("apt update")
        run_cmd(f"apt install -y {' '.join(deps)}")

        # Node & Yarn
        log("Installing Node.js 18.x and yarn globally.")
        run_cmd("curl -sL https://deb.nodesource.com/setup_18.x | bash -")
        run_cmd("apt install -y nodejs npm")
        run_cmd("npm install -g yarn")

        log("[OK] Dependencies installed.")
    else:
        log("[INFO] Skipping dependency installation.")

def configure_database(state):
    log("Configuring PostgreSQL database.")
    print("""
PostgreSQL Database Configuration
---------------------------------
1) Create/Reuse DB & User
2) Return to Main Menu
""")
    choice = input("Choose an option (1/2): ").strip()
    if choice != "1":
        return

    db_name = input("Enter DB name (default: odoo18db): ").strip() or "odoo18db"
    db_user = input("Enter DB user (default: odoo): ").strip() or "odoo"
    db_pass = input("Enter DB password (default: odoo): ").strip() or "odoo"

    # store in state (we do store db_pass temporarily, though we won't save it to JSON)
    state['db_name'] = db_name
    state['db_user'] = db_user
    state['db_pass'] = db_pass

    run_cmd("systemctl enable postgresql && systemctl start postgresql")

    def db_exists(db):
        out, err, rc = run_cmd(f"sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname='{db}'\"",
                               capture_output=True)
        return out.strip() == "1"

    def db_user_exists(user):
        out, err, rc = run_cmd(f"sudo -u postgres psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='{user}'\"",
                               capture_output=True)
        return out.strip() == "1"

    if db_user_exists(db_user):
        print(f"[INFO] DB user '{db_user}' already exists.")
        reuse_user_choice = input("Do you want to recreate this user? (y/n): ").strip().lower()
        if reuse_user_choice == "y":
            run_cmd(f"sudo -u postgres psql -c \"DROP ROLE {db_user};\"")
            run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
            log(f"[OK] Re-created user '{db_user}'.")
        else:
            run_cmd(f"sudo -u postgres psql -c \"ALTER USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
            log(f"[OK] Reusing user '{db_user}', updated password.")
    else:
        run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
        log(f"[OK] Created user '{db_user}'.")

    if db_exists(db_name):
        print(f"[INFO] Database '{db_name}' already exists.")
        reuse_db_choice = input("Do you want to recreate this DB? (y/n): ").strip().lower()
        if reuse_db_choice == "y":
            run_cmd(f"sudo -u postgres psql -c \"DROP DATABASE {db_name};\"")
            run_cmd(f"sudo -u postgres psql -c \"CREATE DATABASE {db_name} OWNER {db_user};\"")
            log(f"[OK] Re-created database '{db_name}'.")
        else:
            log(f"[OK] Reusing database '{db_name}'.")
    else:
        run_cmd(f"sudo -u postgres psql -c \"CREATE DATABASE {db_name} OWNER {db_user};\"")
        log(f"[OK] Created database '{db_name}', owned by '{db_user}'.")

    log("[INFO] Database configuration complete.")

def setup_odoo(state):
    log("Setting up / updating Odoo source code.")
    print("\n==== Odoo Setup / Update ====")
    # Load defaults from state or use fallback
    default_ver = state.get('odoo_ver', '18.0')
    odoo_ver = input(f"Odoo version? (default: {default_ver}): ").strip() or default_ver

    default_path = state.get('install_path', '/opt/odoo18')
    install_path = input(f"Install directory? (default: {default_path}): ").strip() or default_path

    default_user = state.get('odoo_user', 'odoo')
    odoo_user = input(f"System user for Odoo? (default: {default_user}): ").strip() or default_user

    print("\nDo you want to use a Python virtual environment for Odoo?\n1) Yes\n2) No (system-wide)")
    use_venv_choice = input("Choose (1/2): ").strip()
    use_venv = (use_venv_choice == "1")

    # Update state
    state['odoo_ver'] = odoo_ver
    state['install_path'] = install_path
    state['odoo_user'] = odoo_user
    state['use_venv'] = use_venv

    # create user if needed
    if user_exists(odoo_user):
        print(f"[INFO] System user '{odoo_user}' already exists.")
        ch = input("Recreate user? (y/n): ").strip().lower()
        if ch == 'y':
            run_cmd(f"userdel -r {odoo_user}")
            run_cmd(f"useradd -m -d {install_path} -U -r -s /bin/bash {odoo_user}")
            log(f"[OK] Re-created user '{odoo_user}'.")
        else:
            log(f"[OK] Reusing existing user '{odoo_user}'.")
    else:
        run_cmd(f"useradd -m -d {install_path} -U -r -s /bin/bash {odoo_user}")
        log(f"[OK] Created user '{odoo_user}'.")

    # check if directory has .git
    if os.path.isdir(install_path):
        git_path = os.path.join(install_path, ".git")
        if os.path.isdir(git_path):
            print(f"[INFO] Found .git at {install_path}. Reuse or re-clone?")
            ch2 = input("Reuse existing Odoo directory? (y/n): ").strip().lower()
            if ch2 == 'n':
                run_cmd(f"rm -rf {install_path}")
                clone_odoo(odoo_ver, install_path)
        else:
            print(f"[WARN] {install_path} exists but no .git.")
            fix = input("Remove and clone fresh? (y/n): ").strip().lower()
            if fix == 'y':
                run_cmd(f"rm -rf {install_path}")
                clone_odoo(odoo_ver, install_path)
            else:
                log("[WARN] Skipping clone. Directory may be incomplete.")
    else:
        clone_odoo(odoo_ver, install_path)

    # chown
    run_cmd(f"chown -R {odoo_user}:{odoo_user} {install_path}")

    # venv
    if use_venv:
        venv_path = os.path.join(install_path, "venv")
        if os.path.isdir(venv_path):
            print("[INFO] venv exists. Recreate? (y/n)")
            c = input().strip().lower()
            if c == 'y':
                run_cmd(f"rm -rf {venv_path}")
                create_venv(venv_path)
        else:
            create_venv(venv_path)

        install_requirements_venv(install_path, venv_path)
    else:
        install_requirements_system(install_path)

    log("[DONE] Odoo setup or update complete.")

def clone_odoo(odoo_ver, install_path):
    log(f"Cloning Odoo branch {odoo_ver} into {install_path}.")
    out, err, rc = run_cmd(
        f"git clone --depth 1 --branch {odoo_ver} https://github.com/odoo/odoo.git {install_path}",
        capture_output=True
    )
    if rc != 0:
        log(f"[ERROR] Git clone failed. Branch might not exist or no network. Return code: {rc}")

def create_venv(path):
    log(f"Creating virtual environment at {path}")
    run_cmd(f"python3 -m venv {path}")
    log("[OK] venv created.")

def install_requirements_venv(install_path, venv_path):
    req_file = os.path.join(install_path, "requirements.txt")
    if not os.path.isfile(req_file):
        log("[WARN] No requirements.txt found in Odoo directory. Skipping pip.")
        return
    cmd = (
        f"bash -c 'source {venv_path}/bin/activate && "
        f"pip install --upgrade pip && "
        f"pip install -r {req_file} && deactivate'"
    )
    run_cmd(cmd)

def install_requirements_system(install_path):
    req_file = os.path.join(install_path, "requirements.txt")
    if not os.path.isfile(req_file):
        log("[WARN] No requirements.txt found in Odoo directory. Skipping system-wide pip install.")
        return
    cmd = f"pip install --upgrade pip && pip install -r {req_file}"
    run_cmd(cmd)

########################################
# Memory / Worker Config
########################################

def prompt_odoo_memory_config(state):
    log("Prompting for Odoo memory-based worker config.")
    mem = detect_system_memory_mb()
    if mem <= 0:
        log("[WARN] Could not detect system memory from /proc/meminfo.")
    else:
        log(f"[INFO] Detected ~{mem} MB system memory.")

    print("\nWe can suggest worker count based on memory. Press ENTER to skip or accept default.")
    default_workers = 2
    if mem >= 4096 and mem < 8192:
        default_workers = 4
    elif mem >= 8192 and mem < 16384:
        default_workers = 6
    elif mem >= 16384:
        default_workers = 8

    workers = input(f"Number of Odoo workers? (default {default_workers}): ").strip()
    if not workers:
        workers = str(default_workers)
    state['workers'] = workers
    log(f"[OK] Set workers to {workers} (in state only).")

def detect_system_memory_mb():
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

########################################
# ADVANCED POSTGRES TUNING
########################################

def advanced_postgres_tuning():
    log("[INFO] Attempting advanced PostgreSQL memory tuning.")
    print("""
Advanced PostgreSQL Tuning
--------------------------
Set shared_buffers, work_mem, maintenance_work_mem, etc.
Example: 2GB, 16MB, 64MB
""")
    c = input("Proceed? (y/n): ").strip().lower()
    if c != 'y':
        return

    # Usually postgresql 16 in Ubuntu 24.04
    pg_conf = "/etc/postgresql/16/main/postgresql.conf"
    if not os.path.isfile(pg_conf):
        pg_conf = "/etc/postgresql/14/main/postgresql.conf"

    sb = input("shared_buffers (e.g. 2GB) [skip if blank]: ").strip()
    wm = input("work_mem (e.g. 16MB) [skip if blank]: ").strip()
    mm = input("maintenance_work_mem (e.g. 64MB) [skip if blank]: ").strip()

    run_cmd("systemctl stop postgresql")

    with open(pg_conf, 'r') as f:
        lines = f.readlines()

    def set_or_append(param, val, lines):
        found = False
        new_lines = []
        for line in lines:
            if line.strip().startswith(param):
                new_lines.append(f"{param} = {val}\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"\n{param} = {val}\n")
        return new_lines

    new_lines = lines
    if sb:
        new_lines = set_or_append("shared_buffers", sb, new_lines)
    if wm:
        new_lines = set_or_append("work_mem", wm, new_lines)
    if mm:
        new_lines = set_or_append("maintenance_work_mem", mm, new_lines)

    with open(pg_conf, 'w') as f:
        f.write("".join(new_lines))

    run_cmd("systemctl start postgresql")
    log("[OK] Postgres advanced tuning applied.")

########################################
# Configure Odoo
########################################

def configure_odoo(state):
    log("[INFO] Configuring Odoo parameters.")
    db_name = state.get('db_name', 'odoo18db')
    db_user = state.get('db_user', 'odoo')
    db_pass = state.get('db_pass', 'odoo')  # Not saved to JSON; might be missing if user never typed it

    print("\n===== Odoo Configuration =====")
    admin_passwd = input("Master (admin) password? (default: admin): ").strip() or "admin"

    # If db wasn't set up, let them override
    db_host = "localhost"
    db_port = "5432"

    # Worker count
    default_workers = state.get('workers', '4')
    workers = input(f"Workers? (default {default_workers}): ").strip() or default_workers

    print("""
We have optional memory/time limits. 
1) Use recommended defaults 
2) Enter custom values
""")
    c = input("Choose (1/2): ").strip()
    if c == "2":
        limit_memory_hard = input("limit_memory_hard (bytes)? [2GB=2147483648]: ").strip() or "2147483648"
        limit_memory_soft = input("limit_memory_soft (bytes)? [1GB=1073741824]: ").strip() or "1073741824"
        limit_time_cpu   = input("limit_time_cpu (sec)? (default 60): ").strip() or "60"
        limit_time_real  = input("limit_time_real (sec)? (default 120): ").strip() or "120"
        limit_request    = input("limit_request? (default 8192): ").strip() or "8192"
    else:
        limit_memory_hard = "2147483648"
        limit_memory_soft = "1073741824"
        limit_time_cpu   = "60"
        limit_time_real  = "120"
        limit_request    = "8192"

    install_path = state.get('install_path', '/opt/odoo18')
    conf_path = "/etc/odoo.conf"

    content = f"""[options]
; Basic
admin_passwd = {admin_passwd}
db_host = {db_host}
db_port = {db_port}
db_user = {db_user}
db_password = {db_pass}
addons_path = {install_path}/addons
logfile = /var/log/odoo/odoo.log

; Workers / Performance
workers = {workers}
limit_memory_hard = {limit_memory_hard}
limit_memory_soft = {limit_memory_soft}
limit_time_cpu = {limit_time_cpu}
limit_time_real = {limit_time_real}
limit_request = {limit_request}
"""

    ensure_dir("/var/log/odoo")
    odoo_user = state.get('odoo_user', 'odoo')
    run_cmd(f"chown -R {odoo_user}:{odoo_user} /var/log/odoo")

    with open(conf_path, 'w') as f:
        f.write(content)

    run_cmd(f"chown root:root {conf_path} && chmod 640 {conf_path}")
    log(f"[OK] Wrote Odoo configuration to {conf_path}.")

    state['admin_passwd'] = admin_passwd
    state['workers'] = workers
    state['odoo_conf_path'] = conf_path
    log("[INFO] Odoo configuration step complete.")

########################################
# systemd Service
########################################

def create_odoo_service(state):
    log("[INFO] Creating or updating Odoo systemd service.")
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
    log("[OK] Odoo service started or restarted.")
    state['service_file'] = service_file

########################################
# Cloudflare
########################################

def prompt_cloudflare(state):
    log("[INFO] Prompting user for Cloudflare DNS/SSL setup.")
    print("""
Cloudflare Integration
----------------------
We can use acme.sh with Cloudflare DNS API to issue Let's Encrypt certificates automatically.
""")
    c = input("Configure Cloudflare SSL? (y/n): ").strip().lower()
    if c != 'y':
        return

    api_token = input("Enter your Cloudflare API Token: ").strip()
    domain = input("Enter your domain (e.g. example.com): ").strip()
    subdomain = input("Subdomain? (leave empty if root domain): ").strip()

    # store in state, but not in JSON
    state['api_token'] = api_token
    state['cloudflare_domain'] = domain
    state['cloudflare_subdomain'] = subdomain

def setup_cloudflare_ssl(state):
    log("[INFO] Setting up Cloudflare-based SSL via acme.sh.")
    api_token = state.get('api_token')
    domain = state.get('cloudflare_domain')
    subdomain = state.get('cloudflare_subdomain')
    if not api_token or not domain:
        log("[ERROR] Cloudflare not configured (token/domain missing).")
        return

    run_cmd("apt install -y socat")
    run_cmd("curl https://get.acme.sh | sh -s email=my@example.com")

    full_domain = domain
    if subdomain:
        full_domain = f"{subdomain}.{domain}"

    os.environ["CF_Token"] = api_token
    run_cmd(f"~/.acme.sh/acme.sh --issue --dns dns_cf -d {full_domain}")

    run_cmd("mkdir -p /etc/letsencrypt/")
    cmd = (f"~/.acme.sh/acme.sh --install-cert -d {full_domain} "
           f"--key-file /etc/letsencrypt/odoo.key "
           f"--fullchain-file /etc/letsencrypt/odoo.crt "
           f"--reloadcmd \"systemctl reload nginx\"")
    run_cmd(cmd)
    log(f"[OK] SSL certificate installed for {full_domain} in /etc/letsencrypt.")

########################################
# Nginx
########################################

def configure_nginx(state):
    log("[INFO] Configuring Nginx reverse proxy for Odoo.")
    c = input("Do you want to configure Nginx now? (y/n): ").strip().lower()
    if c != 'y':
        return

    domain = state.get('cloudflare_domain', '')
    subd = state.get('cloudflare_subdomain', '')
    if domain:
        if subd:
            domain = f"{subd}.{domain}"
    else:
        domain = input("Enter domain name (e.g. odoo.example.com): ").strip()

    if not domain:
        log("[ERROR] Invalid domain name.")
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
    log(f"[OK] Nginx reverse proxy configured for {domain}.")

########################################
# SSH Hardening
########################################

def harden_ssh():
    log("Prompting for SSH hardening.")
    c = input("Do you want to harden SSH? (y/n): ").strip().lower()
    if c != 'y':
        return

    pub = input("Paste your public SSH key (e.g. ssh-rsa AAAAB3...):\n").strip()
    if not pub.startswith("ssh-"):
        log("[WARN] That doesn't look like a valid SSH key. Skipping.")
        return

    ssh_user = input("Which user do you want to add the key for? (default: root): ").strip() or "root"
    home_dir = "/root" if ssh_user == "root" else f"/home/{ssh_user}"
    ssh_dir = os.path.join(home_dir, ".ssh")

    run_cmd(f"mkdir -p {ssh_dir}")
    auth_file = os.path.join(ssh_dir, "authorized_keys")
    try:
        with open(auth_file, 'a') as f:
            f.write(pub + "\n")
    except Exception as e:
        log(f"[ERROR] Could not write key to {auth_file}: {e}")
        return

    run_cmd(f"chown -R {ssh_user}:{ssh_user} {ssh_dir}")
    run_cmd(f"chmod 700 {ssh_dir}")
    run_cmd(f"chmod 600 {auth_file}")

    disable_pass = input("Disable password login? (y/n): ").strip().lower()
    if disable_pass == 'y':
        sshd_config = "/etc/ssh/sshd_config"
        try:
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
            log("[OK] Password login disabled. Ensure your SSH key works!")
        except Exception as e:
            log(f"[ERROR] Could not edit sshd_config: {e}")

########################################
# Firewall
########################################

def configure_firewall():
    log("Prompting for UFW firewall config.")
    print("""
UFW Firewall Configuration
--------------------------
We'll open ports 22 (SSH), 80 (HTTP), 443 (HTTPS), and optionally 8069 for direct Odoo.
""")
    c = input("Install & enable UFW? (y/n): ").strip().lower()
    if c != 'y':
        return

    run_cmd("apt install -y ufw")

    run_cmd("ufw allow 22")
    run_cmd("ufw allow 80")
    run_cmd("ufw allow 443")
    ch = input("Open Odoo port 8069? (y/n): ").strip().lower()
    if ch == 'y':
        run_cmd("ufw allow 8069")

    run_cmd("ufw enable")
    run_cmd("ufw status")
    log("[OK] UFW firewall configured.")

########################################
# Full Wizard
########################################

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

########################################
# Main Menu
########################################

def main_menu(state):
    while True:
        save_state(state)  # Always save after each action
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
    ensure_dir(os.path.dirname(LOG_FILE))  # ensure /var/log/ exists
    check_root()
    detect_ubuntu()

    # load or init state
    state = load_state()
    main_menu(state)
    save_state(state)
    print("\n[Done] Odoo 18 Setup Script Exiting.\n")

if __name__ == "__main__":
    main()

