import subprocess
import re
import shutil
import sys
from datetime import datetime

def run_command(cmd, output_file, header=None):
    """Run a command and print its output live. Save to a single file."""
    with open(output_file, "a") as f:
        if header:
            f.write(f"\n{'='*30}\n{header}\n{'='*30}\n")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")
            f.write(line)
        process.wait()

def check_dependencies():
    tools = ["nmap", "gobuster", "nikto", "enum4linux", "hydra", "whois", "dig"]
    for tool in tools:
        if not shutil.which(tool):
            print(f"[-] Required tool not found: {tool}")
            sys.exit(1)

def run_nmap_full_scan(target, out_file):
    print(f"\n[*] Running full Nmap port scan on {target}...\n")
    cmd = ["nmap", "-p-", "--open", "-sV", target]

    open_ports = {}
    with open(out_file, "a") as f:
        f.write("\n" + "="*30 + "\nNMAP FULL PORT SCAN\n" + "="*30 + "\n")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")
            f.write(line)
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                port = m.group(1)
                service = m.group(2)
                open_ports[port] = service.lower()
        process.wait()
    print("\n[+] Nmap scan complete.\n")
    return open_ports

def run_gobuster(target, port, out_file, wordlist="/usr/share/wordlists/dirb/common.txt"):
    url = f"http://{target}:{port}"
    print(f"\n[*] Running Gobuster on {url} ...\n")
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    run_command(cmd, out_file, f"GOBUSTER on {url}")
    print(f"[+] Gobuster scan on port {port} complete.\n")

def run_nikto(target, port, out_file):
    url = f"http://{target}:{port}"
    print(f"\n[*] Running Nikto scan on {url} ...\n")
    cmd = ["nikto", "-h", url]
    run_command(cmd, out_file, f"NIKTO on {url}")
    print(f"[+] Nikto scan on port {port} complete.\n")

def run_enum4linux(target, out_file):
    print(f"\n[*] Running enum4linux on {target} ...\n")
    cmd = ["enum4linux", "-a", target]
    run_command(cmd, out_file, f"ENUM4LINUX on {target}")
    print("[+] SMB enumeration complete.\n")

def run_ftp_anon_check(target, out_file):
    print(f"\n[*] Running FTP anonymous access check on {target} ...\n")
    cmd = ["nmap", "-p", "21", "--script=ftp-anon", target]
    run_command(cmd, out_file, f"FTP-ANON NMAP SCRIPT on {target}")
    print("[+] FTP anonymous scan complete.\n")

def run_whois_and_dns(target, out_file):
    print(f"\n[*] Running whois and dig on {target}...\n")
    run_command(["whois", target], out_file, "WHOIS")
    run_command(["dig", target], out_file, "DIG DNS INFO")
    print("[+] Whois and DNS enumeration complete.\n")

def run_hydra(target, port, out_file):
    print(f"\n[*] Hydra brute-force setup for {target}:{port}")
    service = input("Enter service for Hydra (ftp, ssh, http-get, etc.): ").strip()
    userlist = input("Path to username list: ").strip()
    passlist = input("Path to password list: ").strip()

    if not all([service, userlist, passlist]):
        print("[-] Missing input. Skipping Hydra.")
        return

    print(f"\n[*] Running Hydra against {target}:{port} with service {service}...\n")
    cmd = ["hydra", "-L", userlist, "-P", passlist, "-s", port, target, service]
    run_command(cmd, out_file, f"HYDRA on {service} at port {port}")
    print("[+] Hydra brute-force attempt complete.\n")

if __name__ == "__main__":
    check_dependencies()
    target_ip = input("Enter target IP or domain: ").strip()
    if not target_ip:
        print("[-] No target provided.")
        exit()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"recon_results_{target_ip.replace('.', '_')}_{timestamp}.txt"

    print(f"[+] All results will be saved to: {out_file}")

    run_whois_and_dns(target_ip, out_file)

    open_ports = run_nmap_full_scan(target_ip, out_file)

    for port, service in open_ports.items():
        print(f"\n[+] Port {port}: service = {service}")

        if "smb" in service:
            run_enum4linux(target_ip, out_file)
        elif "ftp" in service:
            run_ftp_anon_check(target_ip, out_file)

        if any(web in service for web in ["http", "https", "ssl", "apache", "nginx"]):
            run_gobuster(target_ip, port, out_file)
            run_nikto(target_ip, port, out_file)

        brute = input(f"[*] Attempt Hydra brute-force on {service} at port {port}? (y/n): ").strip().lower()
        if brute == 'y':
            run_hydra(target_ip, port, out_file)
        else:
            print("[-] Skipping Hydra for this port.\n")

