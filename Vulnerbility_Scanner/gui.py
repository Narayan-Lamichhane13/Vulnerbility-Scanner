# Graphical user interface for the vulnerability scanner
# Provides an easy-to-use front-end for scanning and result viewing

import tkinter as tk
from tkinter import messagebox
from vulnerability_scanner import VulnerabilityScanner
import threading

# Global scanner instance
scanner = None

def start_scan():
    # Initiate a new scan based on user input
    # Run scan in background thread to keep GUI responsive
    global scanner
    target = target_entry.get().strip()
    scan_type = scan_type_var.get()

    if not target:
        messagebox.showerror("Input Error", "Please enter a target network or IP.")
        return

    scanner = VulnerabilityScanner(target, scan_type)
    # Daemon thread so it won't block app exit
    t = threading.Thread(target=run_scan, daemon=True)
    t.start()

def run_scan():
    # Execute the actual scanning process
    # Update results in GUI when complete
    try:
        scanner.start_scan()
        results = scanner.get_results()
        # Update GUI on main thread
        results_text.after(0, lambda: update_results(results))
    except Exception as e:
        results_text.after(0, lambda: messagebox.showerror("Scan Error", str(e)))

def update_results(results):
    # Safely update GUI with scan results from background thread
    results_text.delete('1.0', tk.END)
    results_text.insert(tk.END, results)

def export_csv():
    # Export scan results to CSV format
    if scanner and scanner.results:
        scanner.export_results_csv()
        messagebox.showinfo("Export Complete", "Results exported to scan_results.csv.")
    else:
        messagebox.showwarning("No Data", "No scan results to export.")

def export_json():
    # Export scan results to JSON format
    if scanner and scanner.results:
        scanner.export_results_json()
        messagebox.showinfo("Export Complete", "Results exported to scan_results.json.")
    else:
        messagebox.showwarning("No Data", "No scan results to export.")

# GUI Layout Setup
root = tk.Tk()
root.title("Advanced Vulnerability Scanner")

# Input Section: Network target and scan type selection
# Target input
tk.Label(root, text="Target Network/IP:").pack(pady=(10,0))
target_entry = tk.Entry(root, width=50)
target_entry.pack(pady=(0,10))

# Scan type selection
tk.Label(root, text="Scan Type:").pack()
scan_type_var = tk.StringVar(value="TCP")
tk.Radiobutton(root, text="TCP", variable=scan_type_var, value="TCP").pack()
tk.Radiobutton(root, text="UDP", variable=scan_type_var, value="UDP").pack()

# Control Section: Scan and export buttons
# Start Scan button
tk.Button(root, text="Start Scan", command=start_scan).pack(pady=(10,5))

# Export buttons
tk.Button(root, text="Export to CSV", command=export_csv).pack()
tk.Button(root, text="Export to JSON", command=export_json).pack(pady=(0,10))

# Results Section: Scrollable text area for scan results
# Results display
results_text = tk.Text(root, height=20, width=80)
results_text.pack(padx=10, pady=(0,10))

# Start GUI event loop
root.mainloop()
