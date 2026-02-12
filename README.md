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
## 📺 Project Demo
> [Link to your YouTube Video]
*In this video, I walk through the Splunk installation process, the Snort configuration, and a live demonstration of detecting a Brute-Force attack in real-time.

This repository documents the end-to-end creation of a Security Operations Center (SOC) lab. Unlike basic setups, this project involved the manual installation and tuning of the entire defensive stack to identify and mitigate real-world attack vectors.

---

## 🛠️ Phase 1: Infrastructure & Installation
[cite_start]I architected and built the environment from scratch to ensure a deep understanding of log pipelines[cite: 16].

* [cite_start]**Splunk Enterprise:** Performed manual installation on Linux, configuring indexes and data inputs[cite: 9].
* [cite_start]**Universal Forwarders:** Deployed and configured forwarders on Windows/Linux endpoints to centralize log management[cite: 17].
* [cite_start]**Sensor Deployment:** Installed and tuned **Snort IDS** and **Zeek (Bro)** for network-level monitoring[cite: 9, 18].
* [cite_start]**Configuration:** Managed `inputs.conf` and `outputs.conf` to ensure high-fidelity data ingestion into the SIEM[cite: 9].

## ⚔️ Phase 2: Attack Simulation & Impact
[cite_start]To test the lab, I executed controlled attacks to observe the log signatures and measure detection impact[cite: 18].

### 1. Brute-Force Attack (RDP/SSH)
* **Action:** Simulated a high-volume credential stuffing attack.
* [cite_start]**Log Evidence:** Identified **Event ID 4625** (Failed Logons) within Splunk[cite: 21].
* [cite_start]**Detection Impact:** Authored SPL queries to trigger alerts when failed logons exceeded a specific threshold, reducing triage noise[cite: 21].

### 2. Network Reconnaissance & Exploitation
* [cite_start]**Action:** Executed **ARP Poisoning** and **SYN Flood** attacks to test network sensors[cite: 19].
* [cite_start]**Detection:** Utilized **Snort** signatures and **Zeek** flow logs to identify anomalous traffic patterns[cite: 18].
* [cite_start]**Analysis:** Captured and analyzed traffic via **Wireshark** to document packet-level Indicators of Compromise (IOCs)[cite: 19].

## 📈 Phase 3: Detection Engineering (SPL)
[cite_start]I developed custom Splunk dashboards to visualize the attack surface[cite: 9]:
* [cite_start]**High-Fidelity Alerts:** Tuned queries for **Event ID 4688** to monitor suspicious process creations[cite: 21].
* [cite_start]**Automation:** Linked detection alerts to a **Python framework** that automatically cross-references source IPs with **AbuseIPDB**, reducing manual triage time by **30%**[cite: 20].

---

## 📊 Technical Skills Demonstrated
* [cite_start]**SIEM Engineering:** Splunk Installation, Field Extractions, and SPL Optimization[cite: 9].
* [cite_start]**Network Security:** PCAP Analysis, IDS Rule Tuning (Snort/Zeek), and Traffic Analysis[cite: 10, 12, 18].
* [cite_start]**Incident Response:** Threat Hunting, IOC Extraction, and Attack Lifecycle Documentation[cite: 13, 19].
* [cite_start]**Security Automation:** REST API integrations and Python scripting for SOC workflows[cite: 11, 20].

---



# 🤖 Security Automation Engine: IOC Extractor & Threat Intel
### Automating Triage with Python & REST APIs

This repository contains a Python-based framework designed to streamline the initial phases of incident response by automating the extraction and validation of Indicators of Compromise (IOCs).

## 🚀 Impact
* [cite_start]**Efficiency:** Reduced manual triage time by **30%**[cite: 20].
* [cite_start]**Accuracy:** Eliminated manual entry errors by utilizing **Regular Expressions** for precise extraction[cite: 11].

## 🛠️ Key Features
* [cite_start]**Automated Extraction:** Parses raw logs to identify IP addresses, hashes, and URLs using **RegEx**[cite: 11, 20].
* [cite_start]**API Integration:** Cross-references extracted IPs with the **AbuseIPDB API** to check for malicious reputation scores[cite: 13, 20].
* [cite_start]**Security Workflow:** Designed for modular integration into larger security workflows[cite: 6].

## 💻 Tech Stack
* [cite_start]**Language:** Python[cite: 6, 11].
* [cite_start]**Libraries:** Requests (for REST APIs), Re (Regular Expressions)[cite: 11, 20].
* [cite_start]**Intelligence:** AbuseIPDB, VirusTotal API[cite: 13, 20].

#### 🕵️ [Incident Investigation & PCAP Analysis](https://github.com/Manjotsingh12-cyber)
# 🕵️ Incident Investigation: Deep Packet Analysis
### Investigating Network Threats with Wireshark & PCAP Analysis

This project documents a series of deep-dive investigations into simulated network attacks, focusing on identifying malicious traffic patterns and documenting findings for remediation.

## 🔍 Investigation Scope
* [cite_start]**Protocol Analysis:** Conducted deep-packet analysis of **TCP/IP**, **DNS**, and **HTTP/S** traffic[cite: 12, 19].
* **Threat Identification:** Successfully identified and documented patterns for:
    * [cite_start]**ARP Poisoning:** Analyzing spoofed hardware addresses[cite: 19].
    * [cite_start]**SYN Floods:** Identifying TCP handshake exhaustion attempts[cite: 19].

## 🛠️ Tooling & Methodology
* [cite_start]**Network Analysis:** Used **Wireshark** for granular PCAP inspection[cite: 10, 19].
* [cite_start]**Evidence Documentation:** Created detailed investigation reports mapping behavior to specific network anomalies[cite: 19].
* [cite_start]**Remediation Strategy:** Recommended defensive measures based on traffic signatures identified during the triage process[cite: 5, 19].

## 📊 Skills Demonstrated
* [cite_start]**Network Security Monitoring**[cite: 18].
* [cite_start]**Log Analysis** (Windows Event Logs & Sysmon)[cite: 10].
* [cite_start]**Triage & Investigation**[cite: 5, 19].

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
