# Investigate-Devices-Accidentally-Exposed-to-the-Internet

<p align="center">
  ![image](https://github.com/user-attachments/assets/0b6c6771-5a16-42fa-aeb9-9b3525bcb707)

</p>


# Investigate-Devices-Accidentally-Exposed-to-the-Internet


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Investigation Scenario: # Investigate-Devices-Accidentally-Exposed-to-the-Internet

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.


### High-Level Network-Related IoC Discovery Plan

- **Check `DeviceInfo`** 
- **Use `DeviceLogonEvents`** 


---

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table

I started by searching for failed connection attempts in DeviceNetworkEvents table and discovered 23 failed connections on endpoint `edr-machine`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedConnectionAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by FailedConnectionAttempts desc

```
![image](https://github.com/user-attachments/assets/1a2741e0-255a-4d5d-9383-6b915cb37740)

---

### 2. Searched the `DeviceNetworkEvents` Table

I then ran a query in the DeviceNetworkEvents table to look deeper into the connection attempts between `edr-machine` and port `10.0.0.5` and based on the sequential order of ports I believe a port scan was run.


**Query used to locate event:**

```kql

DeviceNetworkEvents
| where DeviceName == "edr-machine"
| where RemoteIP == "10.0.0.5"
| sort by Timestamp desc

```
![image](https://github.com/user-attachments/assets/40ddbc46-67ac-4dbe-b0cf-b57bea71a61e)

---

### 3. Searched the `DeviceProcessEvents` Table

I pivoted to the DeviceProcessEvents table and found a powershell execution of `portscan.ps1` at Apr 20, 2025 8:12:29 AM.

**Query used to locate events:**

```kql
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath
| sort by Timestamp asc

```

![image](https://github.com/user-attachments/assets/05a0d470-61d8-4566-b024-dc8b389e3412)

---

### 4. Search `DeviceProcessEvents` table for instances of powershell

Just prior to the launch of `portscan.ps1` from powershell I found a `InitiatingProcessParentFileName` of `userinit.exe` which suggests a user initiated powershell session at: Apr 20, 2025 8:12:10 AM.

**Query used to locate events:**

```kql
// Instances of Powershell
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where FileName == "powershell.exe"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, InitiatingProcessParentFileName, LogonId
| sort by Timestamp asc

```
![image](https://github.com/user-attachments/assets/f0bb2bab-89a7-425b-97a3-79878f7d5298)

---

### 5. Search `DeviceLogonEvents` table

I then pivoted to the DeviceLogonEvents table and found that the user account `ds9-cisco` logged in 2 minutes before the script was run at Apr 20, 2025 8:11:30 AM.

**Query used to locate events:**

```kql
//use Logon events to determine if a user initiated the portscan
let SpecificTime = datetime(2025-04-20T13:12:29.9031119Z);
DeviceLogonEvents
| where DeviceName == "edr-machine"
| where Timestamp between ((SpecificTime - 1m) .. (SpecificTime + 1m))
| project Timestamp, ActionType, LogonType, AccountDomain, AccountName
| where ActionType == "LogonSuccess"
| sort by Timestamp desc

```

![image](https://github.com/user-attachments/assets/68044cb0-9238-4fb6-9d11-ab450c83256d)

---

### 6. Search `DeviceProcessEvents`

To confirm user execution of PowerShell, I ran a query that included explorer.exe to verify an interactive login session. The results confirmed that user account `ds9-cisco` launched powershell.exe, which subsequently executed the portscan.ps1 script targeting RemoteIP `10.0.0.5`.

```kql
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where Timestamp between (datetime(2025-04-20T13:11:00Z) .. datetime(2025-04-20T13:13:00Z))
| where FileName == "explorer.exe" or FileName == "powershell.exe"
| project Timestamp, AccountDomain, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, AccountName
| sort by Timestamp desc

```
![image](https://github.com/user-attachments/assets/ab040842-5f25-4f81-92a9-264135180920)

---
### Response:

I immediately isolated `edr-machine` from the network to prevent further lateral movement or scanning. Collected forensic logs and exported relevant artifacts including `portscan.ps1`. Forwarded a detailed report to ds9-cisco's manager and the internal HR/security liaison. Created a case for potential policy violation and escalation.

---


### MITRE ATT&CK TTPs Identified

- **Technique:** PowerShell  
  **ID:** T1059.001  
  **Description:** Execution of PowerShell with `-ExecutionPolicy Bypass` to run a script.

- **Technique:** Command and Scripting Interpreter  
  **ID:** T1059  
  **Description:** Use of PowerShell as a scripting interpreter to execute commands.

#### Defense Evasion

- **Technique:** Bypass User Account Control  
  **ID:** T1548.002  
  **Description:** Use of `-ExecutionPolicy Bypass` to avoid PowerShell execution restrictions.

#### Discovery

- **Technique:** Network Service Scanning  
  **ID:** T1046  
  **Description:** Use of a port scanning script to identify open ports and services on the internal network.

- **Technique:** System Network Connections Discovery  
  **ID:** T1049  
  **Description:** Enumeration of active network connections or mapping of internal hosts.

#### Command and Control

- **Technique:** Ingress Tool Transfer  
  **ID:** T1105  
  **Description:** Download of `portscan.ps1` from an external GitHub repository.


---

## Chronological Event Timeline 

1. **User Login – ds9-cisco**

    **Timestamp:** 2025-04-20T13:11:30Z  
    **Event:** The user account `ds9-cisco` logged into `edr-machine` via an interactive session.  
    **Action:** Successful logon captured in `DeviceLogonEvents`.  
    **Logon Type:** Interactive (likely via RDP or local console access).

2. **Session Initialization – explorer.exe**

    **Timestamp:** 2025-04-20T13:11:36Z  
    **Event:** `explorer.exe` was launched under the `ds9-cisco` session.  
    **Action:** Confirms an interactive user session was fully initialized.  
    **Process Chain:** `winlogon.exe → userinit.exe → explorer.exe`

3. **Initial PowerShell Launch**

    **Timestamp:** 2025-04-20T13:12:10Z  
    **Event:** `powershell.exe` was launched manually during the session.  
    **Action:** No script execution yet, just interactive PowerShell access.  
    **Parent Process:** `explorer.exe`  
    **Command:** `powershell.exe`

4. **Script Execution – Portscan Script (portscan.ps1)**

    **Timestamp:** 2025-04-20T13:12:29Z  
    **Event:** The user `ds9-cisco` executed the `portscan.ps1` script.  
    **Action:** The script was downloaded via `Invoke-WebRequest` and run with bypassed execution policy.  
    **File Path:** `C:\programdata\portscan.ps1`  
    **Process Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  
    **Command:** `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`  
    **Parent Process:** `cmd.exe`, originally launched by PowerShell.

5. **Port Scan Activity**

    **Timestamp Range:** 2025-04-20T13:12:30Z → 13:13:01Z  
    **Event:** The script initiated numerous connection attempts to internal IPs, especially targeting `10.0.0.5`.  
    **Action:** Identified as internal port scanning, likely probing for open services.  
    **Table Reference:** `DeviceNetworkEvents` confirmed failed connections originating from `edr-machine`.


---

## Summary

Through a timeline-based investigation, it was determined that the user account `ds9-cisco` logged into `edr-machine` and initiated a PowerShell session during an active desktop session. Shortly thereafter, a script named `portscan.ps1` was executed, which triggered an internal port scanner targeting IPs in the 10.0.0.0/16 subnet. Logs confirmed 23 failed connections to internal devices, consistent with port scanning behavior. The parent-child process chain and timestamps support that this action was manually initiated by the logged-in user.

---

## Recommendations and Improvements

To reduce the attack surface and mitigate similar behavior in the future, the following measures are recommended:
- Restrict PowerShell usage: Apply Group Policy to limit PowerShell usage to administrators or known automation accounts.
- Constrain Execution Policy: Set organization-wide default PowerShell Execution Policy to AllSigned or Restricted.
- Implement AppLocker or WDAC: Block unapproved script execution paths such as C:\programdata\ or C:\Users\Public\.
- Monitor for Suspicious Web Requests: Enable alerts for Invoke-WebRequest and similar tools accessing external domains.
- Enable Network Segmentation: Prevent unrestricted communication across all devices on the internal subnet.
- User Awareness Training: Educate employees about acceptable use policies and risks associated with internal scanning or scripting tools.

