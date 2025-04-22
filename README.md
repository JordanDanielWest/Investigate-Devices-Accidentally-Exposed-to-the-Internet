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

**Query used to locate events:**

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

- Permit-RDP-Trusted-Device: to allow administrative access.
- Deny-RDP-Internet: Blocks RDP from public sources.
- Deny-HTTP-HTTPS: Stops web exposure unless explicitly needed.
- Allow-AzureServices: Lets platform services work.
- Allow-Defender: Ensures Microsoft Defender for Endpoint can send telemetry.
- Allow-Windows-Updates: So the VM stays patched.
- Deny-All-Outbound: Locks down unknown traffic — can whitelist more if needed.
- Deny-All-Inbound: Catches everything not explicitly allowed.

![image](https://github.com/user-attachments/assets/c55d7730-c9cc-40ed-8e40-aa2551358768)




---

### 5. Implement Account Lockout Policy


Navigate to: Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy



![image](https://github.com/user-attachments/assets/25198a06-3d62-44aa-b7cf-d2f0855488ae)


---
### Response:

After identifying `windows-target-1` as unintentionally exposed to the public internet, immediate containment measures were applied. A custom NSG `windows-target-1 Isolation` was assigned to the VM's NIC, restricting all outbound communication and allowing only secure RDP access from a trusted administrative IP. Additionally, a local account lockout policy was enforced, limiting login attempts and mitigating brute-force risk. These steps ensure isolation of the affected machine and reduce exposure while further investigation and remediation continue.

---


### MITRE ATT&CK TTPs Identified

MITRE
# MITRE ATT&CK TTPs Relevant to This Lab

##  Initial Access
- **T1078 – Valid Accounts**  
  Brute-force login attempts were observed against the exposed RDP service on the public-facing VM. These attempts came from external IPs trying to guess valid account credentials.

- **T1133 – External Remote Services**  
  The public-facing VM was exposed to the internet via RDP, providing a potential entry point for external attackers trying to gain initial access through external remote services.

---

##  Credential Access
- **T1110 – Brute Force**  
  Multiple brute-force login attempts from external IP addresses were observed, targeting the RDP service. Although these attempts were unsuccessful, the risk of a successful brute-force attack was significant.

---

##  Mitigation Steps Taken
- **M1030 – Network Segmentation**  
  A custom Network Security Group (NSG) was created and associated with the VM to isolate it from the internet and restrict inbound RDP access. This mitigates the risk of unauthorized external access to the machine.

- **M1036 – Account Use Policies**  
  An account lockout policy was configured to mitigate brute-force attacks. Accounts will be locked after five failed login attempts for a period of 15 minutes, significantly reducing the likelihood of successful brute-force login attempts.



---

## Conclusion
In this lab, we observed and mitigated brute-force login attempts targeting an exposed VM. The primary steps taken to reduce the risk of future attacks included isolating the machine using a custom NSG, implementing an account lockout policy, and used Defender for Endpoint to detect suspicious activities. These actions were aligned with best practices for securing exposed devices and preventing credential-based attacks.


---

