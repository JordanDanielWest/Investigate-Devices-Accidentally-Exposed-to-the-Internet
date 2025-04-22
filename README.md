<p align="center">
  <img src=https://github.com/user-attachments/assets/0b6c6771-5a16-42fa-aeb9-9b3525bcb707>

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

### 1. Searched the `DeviceInfo` Table

`Windows-target-1` has been internet facing for several days.

**Query used to locate events:**

```kql
//Check how long target device has been internet facing
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
|order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/d2752e30-c01a-4c1d-b449-bae7cfeae5a0)

Last internet facing time was: 2025-04-22T17:49:17.4752262Z

---

### 2. Searched the `DevicelogonEvents` Table

Ran a query in `DeviceLogonEvents` to identify potential brute force attempts.

**Query used to locate event:**

```kql

// Check most failed logons
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts


```
![image](https://github.com/user-attachments/assets/d80f3f2c-d1db-483c-820d-faad5ecc6bf3)

---

### 3. Searched the `DeviceLogonEvents` Table

I then searched the top IP’s to determine if any were successful and returned no results.

**Query used to locate events:**

```kql
// Take the top 10 IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["197.210.194.240","103.20.195.132", "64.251.180.218", "180.193.221.205", "147.135.222.78", "135.125.90.97", "178.20.129.235", "80.253.246.51", "192.248.104.29", "90.63.253.204"]);
DeviceLogonEvents
|where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
---

### 4. Create custom NSG for `windows-target-1`

I pivoted to Azure and created a custom NSG for “windows-target-1” to isolate it from external traffic.

- Allow-RDP-Personal-Device: to allow administrative access
- Deny-RDP-Internet: Blocks RDP from public sources.
- Deny-HTTP-HTTPS: Stops web exposure unless explicitly needed.
- Allow-AzureServices: Lets platform services (like health probes) work.
- Allow-Defender: Ensures Microsoft Defender for Endpoint can send telemetry.
- Allow-Windows-Updates: So the VM stays patched.
- Deny-All-Outbound: Locks down unknown traffic — can whitelist more if needed.
- Deny-All-Inbound: Catches everything not explicitly allowed.


![image](https://github.com/user-attachments/assets/b1a8b2fe-18a8-4572-8475-67e563a49939)



---

### 5. Edit Lockout Account policy


Edit Lockout Account policy


![image](https://github.com/user-attachments/assets/25198a06-3d62-44aa-b7cf-d2f0855488ae)


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

