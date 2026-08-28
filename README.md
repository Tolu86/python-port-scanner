# 🔐 Python Port Scanner & Security Assessment Dashboard

A Python-based network reconnaissance and security assessment tool designed to identify open ports, detect services, fingerprint operating systems, perform security analysis, and provide vulnerability intelligence through a web-based dashboard.

> **Educational & Authorized Use Only:** This project is intended for cybersecurity education, testing, and authorized security assessments. Only scan systems and networks that you own or have explicit permission to test.

---

## 📌 Overview

The **Python Port Scanner** is a modular cybersecurity tool that combines traditional network reconnaissance with automated security analysis.

The scanner can perform:

* TCP port scanning
* UDP scanning
* Service detection
* Service version detection
* Banner detection
* TLS/SSL information gathering
* Operating system fingerprinting
* Security risk analysis
* Vulnerability intelligence
* JSON report generation
* CSV report generation
* HTML security reports
* Real-time scan progress
* Web-based dashboard

The project is designed with a modular architecture so that individual components can be developed and improved independently.

---

## ✨ Features

### 🔎 TCP Port Scanning

Supports multiple scanning profiles:

| Profile | Description                                         |
| ------- | --------------------------------------------------- |
| Quick   | Scans a small list of commonly used ports           |
| Common  | Scans a larger collection of commonly exposed ports |
| Full    | Scans all TCP ports from `1-65535`                  |
| Custom  | Allows specific ports or port ranges                |

Examples:

```bash
python scanner.py 127.0.0.1 --quick
```

```bash
python scanner.py 192.168.1.1 --common
```

```bash
python scanner.py 192.168.1.1 --full
```

Custom ports:

```bash
python scanner.py 192.168.1.1 -p 22,80,443
```

Port ranges:

```bash
python scanner.py 192.168.1.1 -p 1-1000
```

---

### 🌐 UDP Scanning

The scanner can perform UDP reconnaissance using:

```bash
python scanner.py 127.0.0.1 --quick --udp
```

UDP results are incorporated into the final scan output.

---

### 🧩 Service Detection

When an open TCP port is discovered, the scanner attempts to identify:

* Service
* Version
* Banner
* Information
* Detection method
* Confidence level

Example:

```text
PORT     STATE    SERVICE       VERSION
22       OPEN     SSH           OpenSSH
80       OPEN     HTTP          Apache
443      OPEN     HTTPS         nginx
```

---

### 🔒 TLS / SSL Analysis

For services supporting TLS, the scanner can collect information such as:

* TLS version
* Cipher
* Cipher strength
* Certificate subject
* Certificate issuer
* Certificate validity period
* Current certificate validity

This helps identify potentially weak or misconfigured encrypted services.

---

### 🖥️ Operating System Fingerprinting

The scanner performs basic OS fingerprinting using network characteristics such as:

* Observed TTL
* Open services
* Service clues

Example:

```text
Estimated OS: Windows
Confidence: MEDIUM
Reason: Observed TTL=128
```

OS fingerprinting is an estimation rather than a guaranteed identification.

---

### 🛡️ Security Analysis

The scanner analyzes discovered services and assigns security findings based on potential exposure.

Findings can include severity levels such as:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Each finding can contain:

* Port
* Severity
* Title
* Description
* Recommended remediation

Example:

```text
HIGH
SMB service exposed

SMB is reachable over the network.

Recommendation:
Restrict SMB access to trusted networks and hosts.
Keep the operating system and SMB software patched.
```

---

### 🚨 Vulnerability Intelligence

The scanner includes a vulnerability analysis component that evaluates detected services and produces vulnerability-related results.

The results are included in the final scan output and reports.

---

### 📊 Web Dashboard

The project includes a Flask-based web dashboard for interacting with the scanner.

The dashboard provides:

* Target input
* Scan profile selection
* UDP scanning
* Real-time progress
* Open-port results
* OS fingerprint information
* Security findings
* Vulnerability information
* Scan statistics

Start the dashboard with:

```bash
python dashboard.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## 🏗️ Project Architecture

```text
                    ┌──────────────────────┐
                    │      Web Dashboard   │
                    │        Flask         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      scanner.py      │
                    │   Scanner Controller  │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
      ┌────────────┐    ┌────────────┐    ┌─────────────┐
      │ TCP Scan   │    │ UDP Scan   │    │ OS Fingerprint│
      └─────┬──────┘    └─────┬──────┘    └──────┬──────┘
            │                 │                  │
            ▼                 ▼                  ▼
      ┌────────────┐    ┌────────────┐    ┌─────────────┐
      │  Service   │    │ UDP Probe  │    │ TTL / Service│
      │ Detection  │    │  Results   │    │    Clues     │
      └─────┬──────┘    └────────────┘    └─────────────┘
            │
            ▼
      ┌────────────────────┐
      │ Security Analysis  │
      └──────────┬─────────┘
                 │
                 ▼
      ┌────────────────────┐
      │ Vulnerability Scan │
      └──────────┬─────────┘
                 │
                 ▼
      ┌────────────────────┐
      │ Results & Reports  │
      │ JSON / CSV / HTML  │
      └────────────────────┘
```

---

## 📁 Project Structure

```text
Port scanner/
│
├── scanner.py
├── dashboard.py
│
├── service_detector.py
├── udp_scanner.py
├── os_fingerprint.py
├── security_checks.py
├── vulnerability_scanner.py
├── report_generator.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ⚙️ Requirements

* Python 3.10+
* Flask
* Windows, Linux, or macOS
* Network access to authorized targets

Python dependencies are listed in:

```text
requirements.txt
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/python-port-scanner.git
```

Move into the project:

```bash
cd python-port-scanner
```

---

### 2. Create a virtual environment

Windows:

```powershell
python -m venv venv
```

Activate it:

```powershell
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
```

```bash
source venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🖥️ Running the Scanner

### Command-Line Scanner

Quick scan:

```bash
python scanner.py 127.0.0.1 --quick
```

Common scan:

```bash
python scanner.py 127.0.0.1 --common
```

Full scan:

```bash
python scanner.py 127.0.0.1 --full
```

UDP scan:

```bash
python scanner.py 127.0.0.1 --quick --udp
```

---

## 📄 Saving Results

### JSON

```bash
python scanner.py 127.0.0.1 --quick --output scan_results.json
```

### CSV

```bash
python scanner.py 127.0.0.1 --quick --csv scan_results.csv
```

### HTML

```bash
python scanner.py 127.0.0.1 --quick --html report.html
```

You can also generate multiple output formats during the same scan.

---

## 🌐 Running the Dashboard

Start Flask:

```bash
python dashboard.py
```

Open:

```text
http://127.0.0.1:5000
```

Enter an authorized target and select the desired scanning options.

---

## 📊 Example Scan Result

Example:

```json
{
    "target": "127.0.0.1",
    "profile": "quick",
    "ports_scanned": 15,
    "open_ports_count": 1,
    "closed_ports_count": 14
}
```

Example security finding:

```json
{
    "port": 445,
    "severity": "HIGH",
    "title": "SMB service exposed",
    "description": "SMB is reachable over the network.",
    "recommendation": "Restrict SMB access to trusted networks and hosts."
}
```

---

## 🔐 Security Considerations

Port scanning can generate network traffic and may be detected by firewalls, intrusion detection systems, or security monitoring tools.

Only scan:

* Your own computer
* Your own servers
* Lab environments
* Systems where you have explicit authorization

Do **not** use this tool to scan unauthorized systems or networks.

---

## 🎯 Project Goals

This project was developed to demonstrate practical cybersecurity and software engineering concepts, including:

* Network reconnaissance
* TCP/IP networking
* Socket programming
* Concurrent programming
* Service identification
* Network security analysis
* OS fingerprinting
* Vulnerability assessment
* Python application development
* Flask web development
* JSON/CSV data processing
* Security reporting

---

## 🔮 Future Improvements

Potential future development includes:

* [ ] Advanced service fingerprinting
* [ ] Improved OS detection
* [ ] Expanded vulnerability database
* [ ] CVE integration
* [ ] CVSS scoring
* [ ] Historical scan comparison
* [ ] Scan scheduling
* [ ] User authentication
* [ ] Database-backed scan history
* [ ] Interactive charts
* [ ] Exportable professional security reports
* [ ] Docker deployment
* [ ] Improved dashboard visualizations
* [ ] Network discovery
* [ ] IPv6 support

---

## 🧪 Testing

The scanner can be tested safely against:

```text
127.0.0.1
```

or other systems that you own or have explicit authorization to assess.

For example:

```bash
python scanner.py 127.0.0.1 --quick
```

---

## 🛠️ Technologies

| Technology         | Purpose               |
| ------------------ | --------------------- |
| Python             | Core scanner          |
| Socket             | Network communication |
| ThreadPoolExecutor | Concurrent scanning   |
| Flask              | Web dashboard         |
| HTML               | Dashboard interface   |
| CSS                | Dashboard styling     |
| JSON               | Scan data storage     |
| CSV                | Data export           |

---

## 👨‍💻 Author

**Ayuba Toluwanimi**

Information & Communication Engineering
Cybersecurity | Networking | Python | Security Engineering

---

## 📜 License

This project is intended primarily for educational and authorized security testing purposes.

Use responsibly and only against systems you are legally permitted to assess.

```
```
