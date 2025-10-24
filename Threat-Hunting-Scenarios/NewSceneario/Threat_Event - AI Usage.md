# Threat Event (Unauthorized Generative AI Usage)
**Unauthorized Generative AI Access and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Connects to ChatGPT website: https://chatgpt.com/
2. Prompts AI and copies generated text
3. Opens Notepad.exe and pastes text
4. Saves AI text under suspicious filenames: "WritingIsEasy.txt", "Imagenius.txt", "Youcantproveanything.txt"

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for detecting text file creation around similar time as AI access. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table|
| **Purpose**| Used to detect the transfer of clipboard text to notepad.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect connection to known generative AI domain ip addresses, specifically ChatGPT (104.18.39.85, 172.64.155.209).|

---

## Related Queries:
```kql
// AI domain ip address == ("172.64.155.209", "142.251.34.206", "23.192.230.141")
// Detect connection to ChatGPT
DeviceNetworkEvents
| where RemoteIP in ("172.64.155.209", "142.251.34.206", "23.192.230.141")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP, InitiatingProcessFileName

// Clipboard data being used
DeviceEvents
| where ActionType == "GetClipboardData"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName

// Fraudulent text files being created
// TimeGenerated fields should be replaced with times corresponding to AI connection
DeviceFileEvents
//| where TimeGenerated between (todatetime('2025-10-23T20:46:52.5019101Z') ..todatetime('2025-10-23T20:59:13.4891584Z') )
| where InitiatingProcessFileName in ("notepad.exe", "winword.exe")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FileSize, FolderPath

// User files were created and, changed, or deleted
DeviceFileEvents
| where FileName has_any ("WritingIsEasy.txt", "Imagenius.txt", "Youcantproveanything.txt")
```

---

## Created By:
- **Author Name**: Daniel Osgood
- **Author Contact**: www.linkedin.com/in/daniel-osgood-672866289
- **Date**: October 23, 2025

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
| 1.0         | Initial draft                  | `October 23, 2025`  | `Daniel Osgood`   
