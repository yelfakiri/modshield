## 🔐 MODSHIELD – Modbus TCP Behavioral Analyzer

### 📌 Description

**MODSHIELD** is a lightweight Python script that analyzes Modbus TCP traffic from `.pcap` files.  
It compares each IP's behavior against predefined rules (`modbus_rules.json`) to detect:

- Use of unauthorized Modbus functions  
- Abnormal or critical commands (e.g., FC5, FC6, FC15, FC16)  
- Suspicious IPs not present in the rule list  

Alerts are written to **`alerts.log`**, with severity levels: **`WARNING`** and **`CRITICAL`**.

---

### 🚀 Usage

#### 🔧 Prerequisites

- Python 3.x  
- `scapy` library

Install the required package:
```bash
pip install scapy
```
#### ▶️ Running the script

Place the following files in your working directory:

- `modshield.py` → main analysis script  
- `modbus_rules.json` → rules per IP and function  
- `ModbusTCP.pcap` → Modbus traffic to analyze

Then run:
```bash
python3 modshield.py
```
---

### 📁 Output

- ✅ A terminal summary (total alerts, critical ones, involved IPs)  
- 📄 A detailed log file: `alerts.log`  

Each log entry includes:

- Timestamp  
- Source and destination IPs  
- Function code used  
- Severity level (WARNING or CRITICAL)

---

### 🌍 Project Language & Ethics

This project was created in the context of an ICS cybersecurity study.  
The logic and use case are based on real observations in industrial environments.  
Some code snippets were validated or supported using AI, and full transparency is maintained: all prompts used to assist with scripting are provided in the annex.

---

### 📎 License

MIT – free to use, modify and adapt with proper credit.
