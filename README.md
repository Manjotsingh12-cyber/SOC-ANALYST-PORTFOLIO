# 🛡️ Manjot Singh | Cyber Defense & SOC Analyst 
### 🔍 Threat Detection | SIEM Monitoring | Security Automation

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/manjot67)

I am a detail-oriented **SOC Analyst** and **BCA candidate** at Chandigarh University.I specialize in building end-to-end detection pipelines, with a focus on **Splunk (SPL)** and **Python automation** to streamline security operations.

---

### 🛠️ Technical Arsenal

**Security Operations (SIEM & IDS)**
* 🔍 **SIEM:** Splunk Enterprise (SPL, Dashboards, Field Extractions).
* 📡 **IDS/NSM:** Snort, Zeek, Wireshark (PCAP Analysis) .
* 📊 **Log Analysis:** Windows Event Logs, Sysmon.

**Automation & Intelligence**
* 🐍 **Programming:** Python for Security Automation and REST APIs. 
* 🌐 **Threat Intel:** VirusTotal API, AbuseIPDB, IOC Extraction .
* 🛠️ **Protocols:** TCP/IP, DNS, HTTP/S, Network Traffic Analysis .

---

### 🧪 Featured Security Projects

#### 🏗️ [Security Operations Home Lab](https://github.com/Manjotsingh12-cyber)
# 🏗️ Advanced SOC Lab: Full-Stack SIEM & IDS Deployment
### Deployment, Configuration, and Attack Simulation 
*In this video, I walk through the Splunk installation process, the Snort configuration, and a live demonstration of detecting a Brute-Force attack in real-time.

This repository documents the end-to-end creation of a Security Operations Center (SOC) lab. Unlike basic setups, this project involved the manual installation and tuning of the entire defensive stack to identify and mitigate real-world attack vectors.

---

## 🛠️ Phase 1: Infrastructure & Installation [![Watch on YouTube](https://img.shields.io/badge/Watch%20on-YouTube-red?logo=youtube&logoColor=white)](https://youtu.be/bKot7h2yYhw)


I architected and built the environment from scratch to ensure a deep understanding of log pipeline.

* **Splunk Enterprise:** Performed manual installation on Linux, configuring indexes and data inputs.
* **Universal Forwarders:** Deployed and configured forwarders on Windows/Linux endpoints to centralize log management.
* **Sensor Deployment:** Installed and tuned **Snort IDS** and **Zeek (Bro)** for network-level monitoring.
* **Configuration:** Managed `inputs.conf` and `outputs.conf` to ensure high-fidelity data ingestion into the SIEM.

## ⚔️ Phase 2: Attack Simulation & Impact
To test the lab, I executed controlled attacks to observe the log signatures and measure detection impact.

### 1. Brute-Force Attack (RDP/SSH)[![Watch on YouTube](https://img.shields.io/badge/Watch%20on-YouTube-red?logo=youtube&logoColor=white)](https://youtu.be/TST9h7KGap4)

* **Action:** Simulated a high-volume credential stuffing attack.
* **Log Evidence:** Identified **Event ID 4625** (Failed Logons) within Splunk.
* **Detection Impact:** Authored SPL queries to trigger alerts when failed logons exceeded a specific threshold, reducing triage noise.

### 2. Network Reconnaissance & Exploitation
* **Action:** Executed **ARP Poisoning** and **SYN Flood** attacks to test network sensors.
* **Detection:** Utilized **Snort** signatures and **Zeek** flow logs to identify anomalous traffic patterns.
* **Analysis:** Captured and analyzed traffic via **Wireshark** to document packet-level Indicators of Compromise (IOCs).

## 📈 Phase 3: Detection Engineering (SPL)[![YouTube Badge](https://img.shields.io/badge/YouTube-Watch%20Lab%20Part%202-red?style=for-the-badge&logo=youtube&logoColor=white)](https://youtu.be/pNxj-hasnR0?si=rfzniDTcnTft7S3Z)
I developed custom Splunk dashboards to visualize the attack surface:
* **High-Fidelity Alerts:** Tuned queries for **Event ID 4688** to monitor suspicious process creations.
* **Automation:** Linked detection alerts to a **Python framework** that automatically cross-references source IPs with **AbuseIPDB**, reducing manual triage time by **30%**.

---

## 📊 Technical Skills Demonstrated
* **SIEM Engineering:** Splunk Installation, Field Extractions, and SPL Optimization.
* **Network Security:** PCAP Analysis, IDS Rule Tuning (Snort/Zeek), and Traffic Analysis.
* **Incident Response:** Threat Hunting, IOC Extraction, and Attack Lifecycle Documentation.
* **Security Automation:** REST API integrations and Python scripting for SOC workflows.

---



# 🤖 Security Automation Engine: IOC Extractor & Threat Intel
### Automating Triage with Python & REST APIs[![GitHub Repo](https://img.shields.io/badge/GitHub-Threat--Intel--Automation-blue?logo=github)](https://github.com/Manjotsingh12-cyber/threat-intel-automation)


This repository contains a Python-based framework designed to streamline the initial phases of incident response by automating the extraction and validation of Indicators of Compromise (IOCs).

## 🚀 Impact
* **Efficiency:** Reduced manual triage time by **30%**.
* **Accuracy:** Eliminated manual entry errors by utilizing **Regular Expressions** for precise extraction.

## 🛠️ Key Features
* **Automated Extraction:** Parses raw logs to identify IP addresses, hashes, and URLs using **RegEx**.
* **API Integration:** Cross-references extracted IPs with the **AbuseIPDB API** to check for malicious reputation scores.
* **Security Workflow:** Designed for modular integration into larger security workflows.

## 💻 Tech Stack
* **Language:** Python.
* **Libraries:** Requests (for REST APIs), Re (Regular Expressions).
* **Intelligence:** AbuseIPDB, VirusTotal API.

#### 🕵️ [Incident Investigation & PCAP Analysis](https://github.com/Manjotsingh12-cyber)
# 🕵️ Incident Investigation: Deep Packet Analysis
### Investigating Network Threats with Wireshark & PCAP Analysis

This project documents a series of deep-dive investigations into simulated network attacks, focusing on identifying malicious traffic patterns and documenting findings for remediation.

## 🔍 Investigation Scope
* **Protocol Analysis:** Conducted deep-packet analysis of **TCP/IP**, **DNS**, and **HTTP/S** traffic.
* **Threat Identification:** Successfully identified and documented patterns for:
    * **ARP Poisoning:** Analyzing spoofed hardware addresses.
    * **SYN Floods:** Identifying TCP handshake exhaustion attempts.

## 🛠️ Tooling & Methodology
* **Network Analysis:** Used **Wireshark** for granular PCAP inspection.
* **Evidence Documentation:** Created detailed investigation reports mapping behavior to specific network anomalies.
* **Remediation Strategy:** Recommended defensive measures based on traffic signatures identified during the triage process.

## 📊 Skills Demonstrated
* **Network Security Monitoring**.
* **Log Analysis** (Windows Event Logs & Sysmon).
* **Triage & Investigation**.

### 🏆 Certifications & Achievements
* 🥇 **SOC L1 (TryHackMe):** Ranked in the **Top 1% Globally**.
* 🎓 **Google Cybersecurity Professional Certificate**.
* 🗣️ **IELTS:** 6.5 Bands (Proficient).

---

### 📊 GitHub Activity
![Manjot's Stats](https://github-readme-stats.vercel.app/api?username=Manjotsingh12-cyber&show_icons=true&theme=tokyonight)
![Top Langs](https://github-readme-stats.vercel.app/api/top-langs/?username=Manjotsingh12-cyber&layout=compact&theme=tokyonight)

---

### 📫 Secure Communications
* 💼 **LinkedIn:** [linkedin.com/in/manjot67](https://www.linkedin.com/in/manjot67)
* 📧 **Email:** mbrar9766@gmail.com
* 📍 **Location:** Muktsar, Punjab.
