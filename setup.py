#!/usr/bin/env python3

import os
import sys
import subprocess
import platform

def print_ascii_banner():
    banner = r"""
   ____  ____          __
  / __ \/ __ \___  ___/ /
 / / / / /_/ / _ \/ _  / 
/ /_/ / _, _/  __/ __/  
\____/_/ |_|\___/_/     
   O D O O   W i z a r d

====================================
Welcome to the Odoo Installation Wizard
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

def check_python_version():
    """
    Check if Python >= 3.11 is installed.
    Ask user if they want to install/upgrade to 3.11 or 3.12.
    """
    # Quick check for python3 version
    print("\n[Step] Checking Python version...")
    version_output, _ = run_cmd("python3 --version", capture_output=True)
    if version_output:
        # Expect something like "Python 3.11.2"
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

    # Prompt to install or upgrade
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
        # Python 3.12 might not yet be in official Ubuntu repos (depending on Ubuntu version),
        # but let's assume the user has a repo or uses deadsnakes PPA for demonstration:
        run_cmd("apt update && apt install -y software-properties-common")
        run_cmd("add-apt-repository ppa:deadsnakes/ppa -y")
        run_cmd("apt update && apt install -y python3.12 python3.12-venv python3.12-dev")
        run_cmd("update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1")
    else:
        print("[INFO] Continuing without upgrading Python...")

def prompt_install_dependencies():
    """
    Prompt user to install typical system dependencies for Odoo and build.
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

def prompt_db_setup():
    """
    Prompt user for DB setup.
    """
    print("""
Do you want to configure PostgreSQL now?
1) Yes - create DB user & database
2) No  - skip
""")
    choice = input("Choose an option (1/2): ").strip()
    if choice == "1":
        db_name = input("Enter DB name (e.g., odoo18db): ").strip()
        db_user = input("Enter DB user (e.g., odoo): ").strip()
        db_pass = input("Enter DB password: ").strip()
        # Create user & DB
        # Check if postgres is running
        run_cmd("systemctl enable postgresql && systemctl start postgresql")
        run_cmd(f"sudo -u postgres psql -c \"CREATE USER {db_user} WITH ENCRYPTED PASSWORD '{db_pass}';\"")
        run_cmd(f"sudo -u postgres psql -c \"CREATE DATABASE {db_name} OWNER {db_user};\"")
        print(f"[OK] Database {db_name} with user {db_user} created.")
        return db_name, db_user, db_pass
    else:
        print("[INFO] Skipped DB setup.")
        return None, None, None

def prompt_odoo_setup():
    """
    Prompt user for Odoo version, install path, system user, etc.
    """
    print("""
Odoo Setup:
-----------
""")
    odoo_ver = input("Which Odoo version do you want to install? (default 18.0): ").strip()
    if not odoo_ver:
        odoo_ver = "18.0"

    install_path = input("Enter install directory (default: /opt/odoo18): ").strip()
    if not install_path:
        install_path = "/opt/odoo18"

    odoo_user = input("System user for Odoo (default: odoo): ").strip()
    if not odoo_user:
        odoo_user = "odoo"

    print("""
Do you want to use a Python virtual environment for Odoo?
1) Yes
2) No (system-wide)
""")
    venv_choice = input("Choose (1/2): ").strip()
    use_venv = (venv_choice == "1")

    return (odoo_ver, install_path, odoo_user, use_venv)

def setup_odoo(odoo_ver, install_path, odoo_user, use_venv):
    """
    Executes commands to:
    - Create Odoo user
    - Clone Odoo from GitHub
    - Setup venv if chosen
    - Install requirements
    """
    # Create system user
    run_cmd(f"id -u {odoo_user} || useradd -m -d {install_path} -U -r -s /bin/bash {odoo_user}")

    # Clone Odoo
    run_cmd(f"git clone --depth 1 --branch {odoo_ver} https://github.com/odoo/odoo.git {install_path}")

    # Setup venv
    if use_venv:
        run_cmd(f"python3 -m venv {install_path}/venv")
        run_cmd(f"source {install_path}/venv/bin/activate && pip install -r {install_path}/requirements.txt && deactivate")
    else:
        # system-wide
        run_cmd(f"pip install -r {install_path}/requirements.txt")

def prompt_odoo_config(db_name=None, db_user=None, db_pass=None):
    """
    Prompt for Odoo configuration (admin_passwd, etc.)
    Return a dict of config values for writing to config file.
    """
    print("""
Odoo Configuration
------------------
""")
    admin_passwd = input("Master (admin) password for Odoo? (default: admin): ").strip()
    if not admin_passwd:
        admin_passwd = "admin"

    # If user didn't set up DB above, db_name/user/pass might be None
    # We’ll let Odoo handle it if not specified
    if db_name:
        db_host = "localhost"
        db_port = "5432"
    else:
        # Possibly user wants remote DB or skip
        db_host = input("DB Host? (default: False for local socket): ").strip()
        if not db_host:
            db_host = "False"
        db_port = input("DB Port? (default: False): ").strip()
        if not db_port:
            db_port = "False"
        db_user = db_user if db_user else "odoo"
        db_pass = db_pass if db_pass else "False"

    workers = input("Number of worker processes? (default: 2): ").strip() or "2"

    return {
        "admin_passwd": admin_passwd,
        "db_host": db_host,
        "db_port": db_port,
        "db_user": db_user,
        "db_password": db_pass,
        "workers": workers
    }

def write_odoo_config(config_dict, install_path):
    """
    Write /etc/odoo<version>.conf or something similar
    """
    conf_path = f"/etc/odoo.conf"
    content = f"""[options]
; Odoo Configuration File
admin_passwd = {config_dict['admin_passwd']}
db_host = {config_dict['db_host']}
db_port = {config_dict['db_port']}
db_user = {config_dict['db_user']}
db_password = {config_dict['db_password']}
addons_path = {install_path}/addons
logfile = /var/log/odoo/odoo.log
workers = {config_dict['workers']}
"""

    with open(conf_path, 'w') as f:
        f.write(content)

    print(f"[OK] Wrote Odoo configuration to {conf_path}")
    run_cmd(f"mkdir -p /var/log/odoo && chown -R {install_path.split('/')[-1]}: /var/log/odoo")
    run_cmd(f"chown root:root {conf_path} && chmod 640 {conf_path}")

    return conf_path

def create_odoo_service(install_path, odoo_user):
    """
    Create and enable a systemd service.
    """
    service_file = "/etc/systemd/system/odoo.service"
    exec_path = f"{install_path}/odoo-bin"
    # Check if venv
    if os.path.exists(os.path.join(install_path, "venv")):
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
    print("[OK] Odoo service started.")

def prompt_cloudflare():
    """
    Prompt user for Cloudflare integration details.
    We'll attempt to set up acme.sh with DNS-01 challenge.
    """
    print("""
Cloudflare Integration
----------------------
We can use acme.sh with Cloudflare DNS API to issue Let's Encrypt certificates automatically.
""")
    choice = input("Do you want to configure Cloudflare SSL? (y/n): ").strip().lower()
    if choice != 'y':
        return None, None, None

    api_token = input("Enter your Cloudflare API Token: ").strip()
    domain = input("Enter your domain (e.g. example.com): ").strip()

    # Possibly subdomain
    subdomain = input("Subdomain? (leave empty if root domain): ").strip()

    return api_token, domain, subdomain

def setup_cloudflare_ssl(api_token, domain, subdomain):
    """
    Use acme.sh + DNS-01 challenge with CF token for SSL.
    We'll set environment variables for acme.sh, or write them to a file.
    """
    # Install acme.sh if not present
    print("\n[INFO] Installing acme.sh (if not already installed)...")
    run_cmd("apt install -y socat")  # often needed by acme.sh
    run_cmd("curl https://get.acme.sh | sh -s email=my@example.com")

    # Environment variables for Cloudflare
    # acme.sh can use CF_Token and CF_Account_ID, but let's keep it simple.
    os.environ["CF_Token"] = api_token

    full_domain = f"{subdomain}.{domain}" if subdomain else domain
    print(f"\n[INFO] Issuing certificate for {full_domain} via acme.sh using DNS-01 challenge...")

    acme_cmd = f"~/.acme.sh/acme.sh --issue --dns dns_cf -d {full_domain}"
    run_cmd(acme_cmd)

    # Install the certificate to /etc/letsencrypt/odoo:
    install_cmd = f"~/.acme.sh/acme.sh --install-cert -d {full_domain} " \
                  f"--key-file /etc/letsencrypt/odoo.key " \
                  f"--fullchain-file /etc/letsencrypt/odoo.crt " \
                  f"--reloadcmd \"systemctl reload nginx\""
    run_cmd("mkdir -p /etc/letsencrypt/")
    run_cmd(install_cmd)

    print(f"[OK] SSL certificate installed for {full_domain} in /etc/letsencrypt.")

def prompt_nginx_config(full_domain):
    """
    Prompt to configure Nginx as a reverse proxy for Odoo.
    """
    choice = input("Do you want to configure Nginx reverse proxy for Odoo? (y/n): ").strip().lower()
    if choice != 'y':
        return
    # We'll assume the user wants to serve Odoo on 80/443
    config_path = "/etc/nginx/sites-available/odoo"
    conf_content = f"""
server {{
    listen 80;
    server_name {full_domain};

    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {full_domain};

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

    run_cmd(f"ln -s {config_path} /etc/nginx/sites-enabled/odoo")
    run_cmd("systemctl restart nginx")
    print(f"[OK] Nginx reverse proxy configured for {full_domain}.")

def prompt_ssh_hardening():
    """
    Prompt user if they want to harden SSH (add key, disable password).
    """
    choice = input("\nDo you want to harden SSH? (y/n): ").strip().lower()
    if choice != 'y':
        return
    # Ask for public key
    pub_key = input("Paste your public SSH key (e.g. ssh-rsa AAAAB3...):\n").strip()
    if not pub_key.startswith("ssh-"):
        print("[Warning] That doesn't look like a valid SSH key. Skipping.")
        return

    # Add the key to root or the current user
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

def main():
    print_ascii_banner()
    check_root()
    detect_ubuntu()

    # Step 1: Check / upgrade python
    check_python_version()

    # Step 2: Prompt for system dependencies
    prompt_install_dependencies()

    # Step 3: DB Setup
    db_name, db_user, db_pass = prompt_db_setup()

    # Step 4: Odoo Setup
    odoo_ver, install_path, odoo_user, use_venv = prompt_odoo_setup()
    setup_odoo(odoo_ver, install_path, odoo_user, use_venv)

    # Step 5: Odoo Config
    config_vals = prompt_odoo_config(db_name, db_user, db_pass)
    conf_path = write_odoo_config(config_vals, install_path)

    # Step 6: Create systemd service
    create_odoo_service(install_path, odoo_user)

    # Step 7: Cloudflare / acme.sh SSL
    api_token, domain, subdomain = prompt_cloudflare()
    if api_token and domain:
        setup_cloudflare_ssl(api_token, domain, subdomain)
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        # Step 8: Nginx reverse proxy
        prompt_nginx_config(full_domain)

    # Step 9: SSH Hardening
    prompt_ssh_hardening()

    print("\n[Installation Complete]")
    print("=========================================")
    print("Odoo should now be running on port 8069. If you configured")
    print("Nginx and SSL, then your domain should serve Odoo over HTTPS.")
    print("=========================================")

if __name__ == "__main__":
    main()
