import subprocess
import re

def run_command(cmd):
    """Run a command and print its output live."""
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(line, end="")
    process.wait()
    return process.returncode

def run_nmap_full_scan(target):
    print(f"\n[*] Running full Nmap port scan on {target}...\n")
    cmd = ["nmap", "-p-", "--open", "-sV", target]

    open_ports = {}
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(line, end="")
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            port = m.group(1)
            service = m.group(2)
            open_ports[port] = service.lower()
    process.wait()
    print("\n[+] Nmap scan complete.\n")
    return open_ports

def run_gobuster(target, port, wordlist="/usr/share/wordlists/dirb/common.txt"):
    url = f"http://{target}:{port}"
    print(f"\n[*] Running Gobuster on {url} ...\n")
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    run_command(cmd)
    print(f"[+] Gobuster scan on port {port} complete.\n")

def run_searchsploit(service):
    print(f"\n[*] Searching exploits for service: {service} ...\n")
    cmd = ["searchsploit", service]
    run_command(cmd)
    print(f"[+] Searchsploit done for {service}.\n")

def run_nikto(target, port):
    url = f"http://{target}:{port}"
    print(f"\n[*] Running Nikto scan on {url} ...\n")
    cmd = ["nikto", "-h", url]
    run_command(cmd)
    print(f"[+] Nikto scan on port {port} complete.\n")

if __name__ == "__main__":
    target_ip = input("Enter target IP or domain: ").strip()
    if not target_ip:
        print("[-] No target provided.")
        exit()

    open_ports = run_nmap_full_scan(target_ip)

    for port, service in open_ports.items():
        print(f"\n[+] Port {port}: service = {service}")
        
        # Always run searchsploit on service name
        run_searchsploit(service)

        if "http" in service or "ssl" in service:
            run_gobuster(target_ip, port)
            run_nikto(target_ip, port)
        else:
            print(f"[-] Skipping Gobuster and Nikto on port {port} (non-HTTP service).\n")
