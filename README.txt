README.txt - Dependency & Usage Guide for Autoenum Script
---------------------------------------------------------

This script performs:
- Full Nmap port scan (-p-)
- Runs SearchSploit on detected services
- Runs Gobuster and Nikto scans on HTTP/HTTPS ports

---

1. Required Tools (must be installed and in your PATH):

   - nmap
   - gobuster
   - searchsploit (from exploitdb)
   - nikto

Example install commands (Debian/Ubuntu):

   sudo apt update
   sudo apt install nmap gobuster nikto exploitdb

---

2. Python:

   - Python 3.x (usually pre-installed)
   - No additional Python packages required.

---

3. Running the script:

   python3 autoenum_basic.py

   Then enter the target IP or domain when prompted.

---

4. Notes:

   - Ensure tools like nmap, gobuster, searchsploit, and nikto are executable from the command line.
   - The script prints output live to console.
   - Gobuster uses default wordlist: /usr/share/wordlists/dirb/common.txt (adjust if needed).
   - Only runs Gobuster and Nikto on ports with HTTP or SSL services.

---

Happy scanning!
