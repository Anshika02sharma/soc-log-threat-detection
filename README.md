# 🔐 SOC Log Threat Detection System

---

## 📌 Overview

This project simulates a **Security Operations Center (SOC) tool** that analyzes authentication logs to detect brute-force login attempts.

It identifies suspicious IPs, classifies threat levels based on failed attempts, and visualizes attack patterns.

---

## ⚡ Features

* Detects failed login attempts from logs
* Tracks attacker IP addresses
* Classifies threats (LOW / MEDIUM / HIGH) based on failed attempts
* Generates CSV security reports
* Visualizes attack data using graphs
* Command-line based execution

---

## 🧠 Working

1. Reads authentication logs (`auth.log`)
2. Extracts failed login attempts
3. Counts attempts per IP
4. Applies threshold-based detection
5. Classifies threat levels
6. Generates reports and graph

---

## 📸 Output

### 📊 Graph Output

![Graph](https://github.com/Anshika02sharma/soc-log-threat-detection/raw/main/graph.png)

---

### 🖥️ Terminal Output

![Terminal](https://github.com/Anshika02sharma/soc-log-threat-detection/raw/main/output.png)

---

## ▶️ How to Run

```bash
python3 log_analyzer.py auth.log
```

### Custom Threshold

```bash
python3 log_analyzer.py auth.log --threshold 3
```

---

## 📂 Project Structure

```
soc-log-threat-detection/
├── log_analyzer.py
├── auth.log
├── attack_report.csv
├── security_report.txt
├── graph.png
├── output.png
└── README.md
```

---

## 🎯 Use Case

* Detect brute-force attacks
* Monitor suspicious login activity
* Perform basic security analysis

---

## 🚀 Future Improvements

* Web dashboard (Flask / Streamlit)
* Real-time log monitoring
* Email alert system
* Integration with threat intelligence APIs

---

## 👩‍💻 Author

**Anshika Sharma**
