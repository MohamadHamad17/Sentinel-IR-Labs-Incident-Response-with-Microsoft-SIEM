# Potential Impossible Travel Detection & Incident Response Lab

## 📖 Overview
This project demonstrates how **impossible travel logins** (suspicious logins from multiple geographic regions in a short timeframe) can be **detected** and **investigated** using **Microsoft Sentinel** and **Azure Sign-in Logs**. The workflow begins with raw event collection (**SigninLogs**) and progresses through building **analytics rules**, triggering **alerts**, and performing **incident response** aligned with the **NIST 800-61** framework. The end goal is to illustrate the complete lifecycle: **detection, analysis, containment, eradication, recovery, and post-incident review**.

---

## ⚙️ Environment Setup
The lab environment consisted of:
- **Azure Virtual Machines** used to generate sign-in events.  
- **Microsoft Sentinel** connected to a **Log Analytics Workspace** for **log ingestion** and **SIEM functionality**.  
- **Analytics Rules** configured to detect **impossible travel logins** and automatically generate incidents.  

All **SigninLogs** from user activity were forwarded into Sentinel, enabling **correlation** across multiple entities (**Users, Locations, Devices**).

---

## 🔍 Part 1 — Detection (Impossible Travel)
Some corporations prohibit logins from outside designated regions, the use of non-corporate VPNs, or account sharing. This detection simulates identifying **unusual login patterns** that may indicate account compromise.  

**Sentinel Scheduled Query Rule:**
```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

**Scheduled Analytics Rule Settings:**
- **Rule frequency:** every 4 hours  
- **Lookup time window:** 5 hours  
- **Alert suppression:** stop after firing until reset  
- **Entity mappings:**  
  - **Account → UserId, UserPrincipalName**  
- **Incident grouping:** single case per 24 hours  
- **MITRE ATT&CK mapping:**  
  - **T1078 – Valid Accounts (Credential Access)**  
  - **T1078.004 – Cloud Accounts**  
  - **T1071.001 – Application Layer Protocol: Web Protocols**  

---

## 🚨 Part 2 — Alert & Incident Creation
Once the **query** is validated, the **analytics rule** is enabled in **Sentinel**. The system autonomously generates **alerts** when users log in from **more than 2 locations** within the 7-day window.  

If natural logs don’t exist, simulate the scenario by:  
1. Creating a new **VM**.  
2. Logging into **https://portal.azure.com** from within the VM.  
3. This generates a new login event from a different geographic region (East Coast, East US 2).  

This triggers the **analytics rule**, producing a new **alert** that automatically escalates into an **incident** within Sentinel.

---

## 🛠️ Part 3 — Incident Response Lifecycle
The incident was worked in accordance with the **NIST 800-61** standard.

### Preparation
- **Monitoring rules, tools, and training** were pre-established.  
- **Roles and responsibilities** were documented ahead of time.  

### Detection & Analysis
The **Potential Impossible Travel** incident was triggered by multiple logins across different cities within a short time window.  

Investigators can pivot deeper with the following **analysis query**:

    // Investigate Potential Impossible Travel Instances
```kql
let TargetUserPrincipalName = "Mohamad.Hamad@gmail.com";
let TimePeriodThreshold = timespan(7d); 
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

### Containment, Eradication, and Recovery
- **Containment:** Account was disabled in **Entra ID (Azure AD)** pending investigation.  
- **Eradication:** No malware involved; potential **account compromise** scenario.  
- **Recovery:** User identity verification and credential reset before re-enabling account.  

Investigators may pivot to **AzureActivity** logs to see if the compromised account was used for other malicious activity:
```kql
    AzureActivity
    | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "<azure user id/guid>"
```
### Post-Incident Activities
- Documented findings and lessons learned.  
- Recommended **geo-fencing policies** to limit logins from specific regions.  
- Recommended **conditional access policies** to enforce MFA on risky logins.  

### Closure
The incident was marked as either a **True Positive (account compromise)** or **Benign Positive (false alarm)** depending on findings. Notes were finalized and the case was **closed** in Sentinel.


## 📑 Findings & Notes
- **Impossible travel detection** identified suspicious logins across multiple geographic regions.  
- Alerts help identify potential **account compromise** or **policy violations**.  
- Incident workflow demonstrated how to **detect, analyze, and respond** to credential misuse in cloud environments.  
