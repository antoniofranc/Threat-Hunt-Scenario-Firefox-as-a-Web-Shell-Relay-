# Threat Event (Firefox Used as a Web Shell Relay)
**Detection of Unauthorized Firefox Installation and Malicious Activity on Workstation: snet**

## Steps the "Bad Actor" took Create Logs and IoCs:

1. Initial Compromise: Downloaded a trojanized Firefox installer disguised as a legitimate file (`Firefox Installer.exe`) to `C:\Users\employee0\Downloads\` at 04:29:57 UTC from what appeared to be Mozilla's official CDN.

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
// 1. Identify Firefox or suspicious installer download activity
DeviceFileEvents
| where FileName contains "firefox" 
| where DeviceName == "snet"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc

// 2. Detect malicious process executions using setup-stub or download.exe
DeviceProcessEvents
| where DeviceName == "snet"
| where FileName in~ ("setup-stub.exe", "download.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc

// 3. Detect Firefox deletion (possible cleanup behavior)
DeviceFileEvents
| where FileName == "firefox.exe"
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, Account, InitiatingProcessCommandLine, FolderPath, SHA256

// 4. Detect network activity to potential malicious endpoints
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("setup-stub.exe", "firefox.exe")
| where RemoteIP has_any ("172.203.80.23")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
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
