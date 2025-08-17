# 🛡️ Sentinel-IR-Labs: Incident Response with Microsoft SIEM  

This repository documents a series of **Incident Response (IR) labs** built using **Microsoft Sentinel (SIEM)**. The goal of these labs is to simulate real-world attack scenarios, onboard security telemetry, and demonstrate end-to-end detection, investigation, and response capabilities within an enterprise environment.  

<img width="1008" height="569" alt="Screenshot 2025-08-17 at 3 11 56 PM" src="https://github.com/user-attachments/assets/6b6af029-e6d3-41b0-a4c6-d04d07853584" />

---

## 🔹 Project Overview  

<img width="768" height="426" alt="Screenshot 2025-08-17 at 3 12 30 PM" src="https://github.com/user-attachments/assets/d0735d15-2f0a-4b52-895a-a7491bf83539" />

I onboarded logs and telemetry from **Microsoft Defender for Endpoint (MDE)** into **Microsoft Sentinel**. Using these data sources, I created **analytic rules** with **KQL** that triggered **incidents** in response to suspicious or malicious activity.  

Each lab simulates realistic attacker behavior inside an organization, and detections are mapped to:  
- **MITRE ATT&CK Framework**  
- **Lockheed Martin Cyber Kill Chain**  
- **NIST SP 800-61 Incident Response Lifecycle**  

---

## 📂 What’s Inside  

- **Log & Telemetry Onboarding**  
  - Integrated Microsoft Defender for Endpoint with Sentinel SIEM  
  - Streamed endpoint logs, alerts, and security events into Sentinel  

- **Detection Rules**  
  - Built KQL-based detections for techniques such as:  
    - Brute force logons  
    - Port scanning / lateral movement  
    - Suspicious PowerShell use  
    - Data staging and exfiltration  
  - Rules aligned with **MITRE TTPs** and **Cyber Kill Chain phases**  

- **Incident Simulation**  
  - Triggered realistic attack scenarios to validate detections  
  - Observed Sentinel automatically spin up incidents based on rules  

- **Incident Response Workflow**  
  - Investigated Sentinel incidents using contextual telemetry  
  - Applied **NIST 800-61** lifecycle: Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned  
  - Documented findings, mapped to MITRE ATT&CK & Kill Chain, and recommended mitigation steps  

---

## 🎯 Purpose  

The purpose of this project is to:  
- Demonstrate **end-to-end incident response** with Microsoft Sentinel  
- Show practical experience in **SIEM detection engineering**  
- Practice simulating realistic attacks and documenting findings  
- Apply structured frameworks (**MITRE, Kill Chain, NIST**) in real-world IR scenarios  

---

## 🛠 Tools & Frameworks Used  

- **Microsoft Azure**  
- **Microsoft Defender for Endpoint (MDE)**  
- **Microsoft Sentinel (SIEM)**  
- **Kusto Query Language (KQL)**  
- **MITRE ATT&CK Framework (TTP mapping)**  
- **Lockheed Martin Cyber Kill Chain (attack phases)**  
- **NIST SP 800-61 Rev. 2** – Incident Response Lifecycle  

---

## ⚔️ Example MITRE ATT&CK & Kill Chain Mapping  

**Scenario:** Port Scanning & Lateral Movement Attempt  

- **MITRE ATT&CK:**  
  - T1046 – Network Service Scanning  
  - T1021 – Remote Services  
- **Cyber Kill Chain Phase:**  
  - **Reconnaissance** → **Delivery** → **Exploitation**  
- **NIST IR Lifecycle Phase:**  
  - Detection & Analysis → Containment  

---

## 📌 Example Detection Rule (Plain Text)  

```kql
DeviceProcessEvents  
| where FileName == "powershell.exe"  
| where ProcessCommandLine contains "Invoke-WebRequest"  
| where InitiatingProcessAccountName != "Administrator"  
```
---

## ✅ Why This Matters  

This project demonstrates:  
- Practical use of **Azure Sentinel SIEM** in detecting and responding to incidents  
- Hands-on knowledge of **threat simulation, detection, and investigation**  
- Ability to apply **structured frameworks** (MITRE, Kill Chain, NIST) in IR workflows  
- Skills in **KQL detection engineering** and **security operations**  

