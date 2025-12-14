# 👻 GhostCr Scanner - Advanced Network Vulnerability Scanner

**GhostCr Scanner** is a robust, multi-threaded network scanner developed in Python. Designed for Red Team operations and security auditing, it leverages raw packet manipulation via `Scapy` to perform stealthy reconnaissance, firewall evasion, and service fingerprinting.

Unlike standard tools, **GhostCr Scanner** manually constructs TCP/IP packets, offering granular control over the scanning logic and avoiding standard detection signatures.

## 🚀 Key Features

* **TCP SYN "Stealth" Scan:** Performs half-open scanning (SYN -> SYN-ACK -> RST), preventing the connection from being fully established and logged by the target.
* **Firewall Evasion Modules:** Implements **XMAS**, **FIN**, and **NULL** scan types to bypass stateless firewalls and identify OS behaviors (RFC 793 compliance checks).
* **Service Banner Grabbing:** Automatically establishes a full TCP connection upon detecting open ports to capture service versions (e.g., `Apache/2.4`, `Python/3.13`).
* **Mass Range Scanning:** Optimized to scan extensive port ranges (e.g., `1-65535`) efficiently.
* **High-Performance Concurrency:** Utilizes **Multithreading** and Queue management to perform hundreds of checks per second.

## 🛠️ Technologies

Key technologies and concepts implemented in this project:
* **Python 3**
* **Scapy** (Raw Socket Manipulation)
* **TCP/IP Protocol Stack** (Handshake mechanics, Flag manipulation)
* **Network Socket Programming**
* **Concurrency** (Threading & Queue management)

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ItsCurulo/GhostCr.git
    cd GhostCr
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

Administrative privileges (`sudo`) are required to craft raw packets.

**Syntax:**
```bash
sudo python3 ghostcr_scanner.py -t <TARGET_IP> -p <PORT_RANGE> -m <MODE> -th <THREADS>
```
**Arguments:**
* `-t`: Target IP address (e.g., `192.168.1.10`).
* `-p`: Port or Range (e.g., `80` or `20-1000`).
* `-m`: Scan Mode (`syn`, `xmas`, `fin`, `null`). Default: `syn`.
* `-th`: Number of threads (Speed). Default: `20`.
    Note: Increasing threads beyond 50 may cause packet loss or inaccuracies due to Scapy's raw socket handling limitations.

**Examples:**

1. **Fast Stealth Scan (Top 1000 ports):**
   ```bash
   sudo python3 ghostcr_scanner.py -t 10.10.10.5 -p 1-1000 -th 20
   ```

2. **Firewall Evasion (XMAS Scan):**
   ```bash
   sudo python3 ghostcr_scanner.py -t 10.10.10.5 -p 80 -m xmas
   ```

**⚠️ Disclaimer**
This tool is developed for educational and ethical security testing purposes only. Scanning networks or devices without explicit permission is illegal. The author accepts no responsibility for unauthorized use.

**Developed by Curulo 🛡️**