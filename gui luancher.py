import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import subprocess

def run_autoenum(target, gobuster, users, passwords, fail_str, output_box):
    output_box.insert(tk.END, f"[*] Starting automation on {target}\n")
    output_box.see(tk.END)

    cmd = [
        "python3", "autoenum.py", target,
        "--gobuster", gobuster,
        "--users", users,
        "--passwords", passwords,
        "--failstr", fail_str
    ]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            output_box.insert(tk.END, line)
            output_box.see(tk.END)
        process.wait()
        output_box.insert(tk.END, "\n[+] Automation completed.\n")
    except Exception as e:
        output_box.insert(tk.END, f"\n[-] Error: {e}\n")

def start_thread():
    target = entry_target.get().strip()
    gobuster = entry_gobuster.get().strip()
    users = entry_users.get().strip()
    passwords = entry_passwords.get().strip()
    fail_str = entry_fail.get().strip()

    if not target:
        messagebox.showerror("Error", "Please enter a target domain or IP")
        return

    threading.Thread(target=run_autoenum, args=(target, gobuster, users, passwords, fail_str, text_output), daemon=True).start()

def browse_wordlist(entry_field):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)

root = tk.Tk()
root.title("CTF Auto Enumeration")

# Target
tk.Label(root, text="Target Domain or IP:").pack()
entry_target = tk.Entry(root, width=50)
entry_target.pack()

# Gobuster wordlist
tk.Label(root, text="Gobuster Wordlist:").pack()
frame_gobuster = tk.Frame(root)
entry_gobuster = tk.Entry(frame_gobuster, width=40)
entry_gobuster.pack(side=tk.LEFT)
tk.Button(frame_gobuster, text="Browse", command=lambda: browse_wordlist(entry_gobuster)).pack(side=tk.LEFT)
frame_gobuster.pack()

# Hydra usernames
tk.Label(root, text="Hydra Usernames List:").pack()
frame_users = tk.Frame(root)
entry_users = tk.Entry(frame_users, width=40)
entry_users.pack(side=tk.LEFT)
tk.Button(frame_users, text="Browse", command=lambda: browse_wordlist(entry_users)).pack(side=tk.LEFT)
frame_users.pack()

# Hydra passwords
tk.Label(root, text="Hydra Passwords List:").pack()
frame_passwords = tk.Frame(root)
entry_passwords = tk.Entry(frame_passwords, width=40)
entry_passwords.pack(side=tk.LEFT)
tk.Button(frame_passwords, text="Browse", command=lambda: browse_wordlist(entry_passwords)).pack(side=tk.LEFT)
frame_passwords.pack()

# Failure string
tk.Label(root, text="Hydra Failure String (e.g., 'invalid')").pack()
entry_fail = tk.Entry(root, width=50)
entry_fail.insert(0, "invalid")
entry_fail.pack()

# Start button
btn_start = tk.Button(root, text="Start Enumeration", command=start_thread)
btn_start.pack(pady=10)

# Output box
text_output = scrolledtext.ScrolledText(root, width=100, height=25)
text_output.pack()

root.mainloop()

