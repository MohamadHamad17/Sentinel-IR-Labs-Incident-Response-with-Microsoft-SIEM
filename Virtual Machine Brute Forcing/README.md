# Brute Force Detection & Incident Response Lab

## 📖 Overview
This project demonstrates how **brute force login attempts** against **Azure-hosted Virtual Machines** can be **detected** and **investigated** using **Microsoft Defender for Endpoint (MDE)** telemetry combined with **Microsoft Sentinel**. The workflow begins with raw event collection (**DeviceLogonEvents**) and progresses through building **analytics rules**, triggering **alerts**, and performing **incident response** aligned with the **NIST 800-61** framework. The end goal is to illustrate the complete lifecycle: **detection, analysis, containment, eradication, recovery, and post-incident review**.

---

## ⚙️ Environment Setup
The lab environment consisted of:
- **Azure Virtual Machines** onboarded into **Defender for Endpoint**, generating **detailed login telemetry**.
- **Microsoft Sentinel** connected to a **Log Analytics Workspace** for **log ingestion** and **SIEM functionality**.
- **Analytics Rules** configured to **detect repeated failed login attempts** and **automatically generate incidents**.
- **Network Security Groups (NSGs)** applied to **restrict network traffic** during **containment phases**.

All **DeviceLogonEvents** generated from **local and remote logon attempts** were forwarded into Sentinel, enabling **correlation** across multiple entities (**Remote IP addresses, Device Names, User accounts**).

---

## 🔍 Part 1 — Brute Force Attempt Detection
The **detection mechanism** is based on **aggregating failed logon attempts** within a **time window**. The **KQL query** leverages the **DeviceLogonEvents table** with filtering on the **ActionType** field. 

<img width="1422" height="731" alt="Screenshot 2025-08-17 at 4 07 21 PM" src="https://github.com/user-attachments/assets/f1c49558-ade3-45d8-a641-ffa6244ffe1c" />

**Sentinel Scheduled Query Rule:**  

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

<img width="1422" height="731" alt="Screenshot 2025-08-17 at 4 11 21 PM" src="https://github.com/user-attachments/assets/8a7e89c9-27a9-4258-85ce-cc5243bb3c39" />

**Scheduled Analytics Rule Settings:**  
- **Rule frequency:** every 4 hours.  
- **Lookup time window:** 5 hours.  
- **Alert suppression:** stop after firing until reset.  
- **Entity mappings:** **RemoteIP** mapped as **attacker**, **DeviceName** mapped as **victim**.  
- **Incident grouping:** all alerts within **24 hours** are rolled into a **single case**.  
- **MITRE ATT&CK mapping:**  
- **Tactic:** **Credential Access**  
- **Technique:** **Brute Force (T1110)**  

---

## 🚨 Part 2 — Alert & Incident Creation
Once the **query** is validated, the **analytics rule** is **enabled** in **Sentinel**. The system is then able to **autonomously generate alerts** when **brute force criteria** are met.  
If insufficient **failed logon attempts** exist naturally, additional **failed attempts** can be induced to generate sufficient telemetry. This triggers the **rule**, producing a new **alert** which automatically escalates into an **incident** within the **Threat Management → Incidents** view of Sentinel.  

<img width="1422" height="731" alt="Screenshot 2025-08-17 at 4 25 16 PM" src="https://github.com/user-attachments/assets/fd3b4e02-a1df-479d-b53e-8cb70433fb1b" />

The **incident object** contains key attributes such as **triggering IP addresses**, **targeted devices**, and the **mapped MITRE techniques**. This provides the foundation for **investigation**.

---

## 🛠️ Part 3 — Incident Response Lifecycle
The incident was worked in accordance with the **NIST 800-61** standard, documenting each phase.

### Preparation
- **Tools, access permissions, and monitoring rules** were pre-established.  
- **Roles** and **escalation procedures** were defined prior to incident occurrence.  

### Detection & Analysis

The **Brute Force Detection – Josh** incident was triggered from **10 different IP addresses** against **2 different hosts**.  
Check to make sure none of the IP addresses attempting to brute force the machine actually logged in. *(Hint: It’s possible to build this into the query to only trigger for apparent successful brute forces).*  
Record Findings.  

The **Brute Force Detection – Josh** incident was triggered from **10 different IP addresses** against **2 different hosts**.  


To check for potential **compromise**, the following **investigative query** was executed, parameterized by **target system** and **suspect IP**:

```kql
let TargetDevice = "john-smith";  
let SuspectIP = "89.116.158.44";  
DeviceLogonEvents  
| where ActionType == "LogonSuccess"  
| where DeviceName == TargetDevice and RemoteIP == SuspectIP  
| order by TimeGenerated desc  
```

This ensured that **failed attempts** did not progress into actual **unauthorized access**.

### Containment, Eradication, and Recovery
- **Containment** was simulated by updating the **NSG** associated with the VM to only allow inbound traffic from the **analyst’s workstation**.  
- In a production environment, **Defender for Endpoint’s isolation feature** would also be leveraged.  
- **Antivirus scans** were run to validate that no **malware** was deployed.  
- As **brute force attempts** were **unsuccessful**, no remediation beyond **containment** was required.  

### Post-Incident Activities
Key lessons included the importance of **pre-configured detection thresholds** and consistent **NSG enforcement**.  
A corporate policy recommendation was documented: all **Azure VMs** must enforce **restricted inbound rules** by default, managed via **Azure Policy** to prevent misconfigurations.  

### Closure
The incident was marked as a **True Positive** brute force attempt but **without successful compromise**. **Documentation** and **notes** were finalized within **Sentinel**, and the case was **closed**.

---

## 🧹 Part 4 — Cleanup
To maintain a clean **lab environment**, the associated **analytics rule** was **removed** from Sentinel and the **closed incident** was **deleted**. Care was taken to ensure only **personal lab objects** were deleted, avoiding interference with **shared environments**.

---

## 📑 Findings & Notes
- **Brute force attempts** were detected from **ten distinct IP addresses** targeting **multiple hosts**.  
- No **successful logons** occurred from malicious IPs, confirming **preventive defenses**.  
- **Sentinel’s incident management** streamlined **triage** and **response**.  
- **NSG lockdown** was effective in simulating **containment**.  
- **Policy hardening** is recommended to avoid exposure of **VMs** to the **public internet**.  

---

## 📚 References
- [**Microsoft Sentinel Documentation**](https://learn.microsoft.com/en-us/azure/sentinel/)  
- [**Defender for Endpoint DeviceLogonEvents Schema**](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-device-logon-events-table)  
- [**MITRE ATT&CK: Brute Force (T1110)**](https://attack.mitre.org/techniques/T1110/)  
- **NIST 800-61: Computer Security Incident Handling Guide**  
