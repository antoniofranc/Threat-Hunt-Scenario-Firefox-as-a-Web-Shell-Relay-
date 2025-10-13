<img width="400" src="https://github.com/user-attachments/assets/5097e215-767a-483b-8538-b12411f0b00d"  alt="Firefox Logo"/>
                        


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/antoniofranc/Threat-Hunt-Scenario-Firefox-as-a-Web-Shell-Relay-/blob/main/threat-hunting-scenario-firefox-as-a-web-shell-relay.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched the DeviceFileEvents table for any file containing the string "tor" and discovered that user "walnet" downloaded a Tor Browser installer. Subsequently, numerous Tor-related files were copied to the Desktop, along with the creation of a file named "tor-shopping-list.txt" at 2025-10-05T01:30:42.6417593Z on the Desktop. These events began on October 5, 2025, 01:18:04 UTC (timestamp: 2025-10-05T01:18:04.9518825Z.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "walnet"  
| where InitiatingProcessAccountName == "walnet"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-10-05T01:18:04.9518825Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1427" height="578" alt="image" src="https://github.com/user-attachments/assets/89e3c64a-645c-4acc-9d33-00d218320769" />


---

### 2. Searched the `DeviceProcessEvents` Table

I searched the DeviceProcessEvents table for any ProcessCommandLine containing the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the returned logs, at October 5, 2025, 01:18:04 UTC (2025-10-05T01:18:04.9518825Z), an employee using the "walnet" device executed the Tor Browser portable installer (version 14.5.7) from their Downloads folder using a silent installation flag (/S) that bypasses all user prompts and installs the software automatically without visible interaction.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "walnet"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1407" height="74" alt="image" src="https://github.com/user-attachments/assets/28125609-9f4e-42a5-ad18-d840c60bdabe" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that user "walnet" actually opened the Tor Browser. Evidence confirmed that the Tor Browser was launched on October 5, 2025, 01:19:20 UTC (2025-10-05T01:19:20.8474222Z). Multiple subsequent instances of firefox.exe (the Tor Browser executable) and tor.exe (the Tor network daemon) were spawned following the initial launch, indicating active and sustained use of the Tor Browser.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "walnet"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1431" height="522" alt="image" src="https://github.com/user-attachments/assets/8938aad7-e359-4f7e-90ff-024d14bb8247" />


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
