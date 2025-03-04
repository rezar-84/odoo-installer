#!/usr/bin/env python3

import os
import sys
import subprocess
import time

def run_cmd(cmd, capture_output=False):
    print(f"[CMD] {cmd}")
    if capture_output:
        result = subprocess.run(cmd, shell=True, check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = result.stdout.decode('utf-8')
        stderr = result.stderr.decode('utf-8')
        if result.returncode != 0:
            print(f"[ERROR] Command failed with code {result.returncode}")
            print(f"STDERR: {stderr}")
        return (stdout, stderr, result.returncode)
    else:
        result = subprocess.run(cmd, shell=True, check=False)
        return ("", "", result.returncode)

def check_root():
    if os.geteuid() != 0:
        print("[ERROR] Must run as root or with sudo.")
        sys.exit(1)

def main():
    check_root()

    print("==> Updating apt and installing software-properties-common")
    run_cmd("apt update")
    run_cmd("apt install -y software-properties-common")

    print("==> Adding deadsnakes PPA for Python 3.12")
    run_cmd("add-apt-repository ppa:deadsnakes/ppa -y")
    run_cmd("apt update")

    print("==> Installing Python 3.12, venv, dev, and build tools")
    pkgs = [
        "python3.12",
        "python3.12-venv",
        "python3.12-dev",
        "build-essential",   # typical dev tools
        "curl",              # ensure we have curl for nvm
        "wget",              # optional
        "git",               # optional if you'd like
    ]
    run_cmd(f"apt install -y {' '.join(pkgs)}")

    print("==> Setting Python 3.12 as default python3 via update-alternatives")
    run_cmd("update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1")
    
    print("==> Checking Python version:")
    run_cmd("python3 --version")

    print("==> Installing nvm (Node Version Manager)")
    # This adds nvm lines to root's (or the user's) bashrc.
    # If you want nvm for a specific user (like 'odoo'), you'd run this as that user
    # or place it in that user's home directory.
    run_cmd("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash")

    # We need to source nvm in the current script to use it immediately:
    # We'll place a small snippet in a temporary shell script to load nvm.
    nvm_loader = "/tmp/load_nvm.sh"
    with open(nvm_loader, "w") as f:
        f.write(r"""
#!/bin/bash
export NVM_DIR="$([ -z "${XDG_CONFIG_HOME-}" ] && printf %s "$HOME/.nvm" || printf %s "$XDG_CONFIG_HOME/nvm")"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
""")
    run_cmd(f"chmod +x {nvm_loader}")

    print("==> Installing Node 22 via nvm")
    # We'll run a shell that sources nvm, then nvm install 22
    cmd_install_node = f"bash -c '. {nvm_loader} && nvm install 22 && nvm alias default 22'"
    run_cmd(cmd_install_node)

    print("==> Enabling Yarn via corepack, verifying versions")
    # We'll also enable corepack, which is built into new Node versions:
    cmd_yarn = f"bash -c '. {nvm_loader} && corepack enable && yarn --version'"
    run_cmd(cmd_yarn)
    
    # Verify final Node, npm, Python versions
    print("==> Final check of Node, npm, yarn, python3:")
    run_cmd(f"bash -c '. {nvm_loader} && node -v'")
    run_cmd(f"bash -c '. {nvm_loader} && npm -v'")
    run_cmd("python3 --version")
    # yarn was printed above

    print("\n[INFO] Dependencies installed: Python 3.12 + nvm + Node 22 + Yarn.\n")

if __name__ == "__main__":
    main()
