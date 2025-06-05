import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess

def run_autoenum(target, output_box):
    output_box.insert(tk.END, f"Starting automation on {target}\n")
    output_box.see(tk.END)
    cmd = ["python3", "autoenum.py", target]

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    for line in process.stdout:
        output_box.insert(tk.END, line)
        output_box.see(tk.END)

    process.wait()
    output_box.insert(tk.END, f"Automation completed.\n")

def start_thread():
    target = entry_target.get().strip()
    if not target:
        messagebox.showerror("Error", "Please enter a target domain or IP")
        return
    threading.Thread(target=run_autoenum, args=(target, text_output), daemon=True).start()

root = tk.Tk()
root.title("CTF Auto Enumeration")

tk.Label(root, text="Target Domain or IP:").pack()
entry_target = tk.Entry(root, width=40)
entry_target.pack()

btn_start = tk.Button(root, text="Start Enumeration", command=start_thread)
btn_start.pack(pady=5)

text_output = scrolledtext.ScrolledText(root, width=80, height=20)
text_output.pack()

root.mainloop()
