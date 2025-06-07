# 🔍 Advanced Vulnerability Scanner

A Python-based tool that scans networks for vulnerabilities using **Nmap**, integrates with the **NVD API**, and provides an easy-to-use GUI built with **Tkinter**.

---

## 🚀 Features
- 🌐 **Network Scanning**: Detects open ports and running services on TCP/UDP.
- 🧩 **CVE Lookup**: Integrates with the NVD API to identify known vulnerabilities in services.
- 🖥️ **Graphical Interface**: Easy-to-use GUI for initiating scans and viewing results.
- 📂 **Export Options**: Save scan results in CSV or JSON formats.
- ⚡ **Multi-threading**: Perform scans faster by scanning multiple hosts simultaneously.

---

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/vulnerability-scanner.git
   cd vulnerability-scanner

---

## 🖥️ Usage
Run the GUI:
python gui.py

Enter Target Details:

Specify the target IP address or network (e.g., 192.168.1.0/24).
Select the scan type (TCP/UDP).
Start Scanning:

Click the Start Scan button to begin the scan.
View results in the GUI's results section.
Export Results:

Click Export to CSV or Export to JSON to save scan results.

---

## 📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## 🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests for improvements.

---

## ❓ FAQs
Why do I get "Nmap not found in PATH"?
Ensure Nmap is installed and its path is added to your system's environment variables.

Can I scan a public network or server?
No. Only scan networks or systems you own or have explicit permission to scan.

