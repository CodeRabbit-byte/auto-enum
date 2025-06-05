import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess

class ScanLauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CTF Enumeration Launcher")
        self.geometry("800x600")
        self.resizable(False, False)

        # Target input
        tk.Label(self, text="Target IP or Domain:", font=("Arial", 12)).pack(pady=(10, 0))
        self.entry_target = tk.Entry(self, width=50, font=("Arial", 12))
        self.entry_target.pack(pady=(0, 10))

        # Start button
        self.btn_start = tk.Button(self, text="Start Scan", font=("Arial", 12, "bold"), command=self.start_scan_thread)
        self.btn_start.pack(pady=(0, 10))

        # Output box (read-only)
        self.output_box = scrolledtext.ScrolledText(self, width=95, height=30, font=("Consolas", 10))
        self.output_box.pack(padx=10, pady=10)
        self.output_box.config(state=tk.DISABLED)  # Make read-only

    def append_output(self, text):
        self.output_box.config(state=tk.NORMAL)
        self.output_box.insert(tk.END, text)
        self.output_box.see(tk.END)
        self.output_box.config(state=tk.DISABLED)

    def run_scan(self, target):
        # Command to run the scanner script (adjust if saved elsewhere)
        cmd = ["python3", "autoenum.py", target]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            for line in process.stdout:
                self.append_output(line)

            process.wait()
            self.append_output("\n[+] Scan completed.\n")
        except Exception as e:
            self.append_output(f"\n[-] Error: {e}\n")

        # Re-enable the start button after scan
        self.btn_start.config(state=tk.NORMAL)

    def start_scan_thread(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return

        # Clear previous output
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete(1.0, tk.END)
        self.output_box.config(state=tk.DISABLED)

        # Disable button during scan
        self.btn_start.config(state=tk.DISABLED)

        # Start the scanning in a thread to keep UI responsive
        thread = threading.Thread(target=self.run_scan, args=(target,), daemon=True)
        thread.start()


if __name__ == "__main__":
    app = ScanLauncher()
    app.mainloop()


