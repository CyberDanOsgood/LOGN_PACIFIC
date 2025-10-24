# Threat Hunt Report (Unauthorized Generative AI Usage)
**Detection of Unauthorized Generative AI Access and Use**

## Scenario:
Management from a news website suspects that an employee may be using Generative AI in order to write wholesale articles and take credit, against company ethical standards. Using an AI detector on one of their articles shows a high chance of AI usage, however management would like some more solid proof before taking action. The studio is not extremely technologically savvy, which means that while they do have MDE set up on their devices, they have not set any rules or proxies to prevent access to specific sites. This also means that the culprit is unlikely to have taken any obfuscation measures to hide their tracks. Correlation of AI access and text file creation should be enough to support action against the employee.

---

## High-Level TOR related IoC Discovery Plan:
1. Check DeviceNetworkEvents for any AI website connection events
2. Check DeviceFileEvents for any signs of text files created around the same time
3. Check DeviceEvents for any signs of clipboard copying and pasting in the same timeframe

---

## Steps Taken

Pinged popular AI sites to get IP addresses in order to properly search through logs (ChatGPT, Google Gemini, Copilot).


Searched DeviceNetworkEvents table for any connection made to ChatGPT, Gemini, or Copilot ip address ("172.64.155.209", "142.251.34.206", "23.192.230.141"). Found only one device that was actively connecting to ChatGPT (threathunting-d) recently at Timestamp: 2025-10-23T20:46:52.5019101Z or 8:46PM
Query used:
DeviceNetworkEvents
| where RemoteIP in ("172.64.155.209", "142.251.34.206", "23.192.230.141")
| where TimeGenerated >= datetime(2025-10-20)
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteIP, InitiatingProcessFileName


Searched DeviceFileEvents for any text or word files being created around the same time as ChatGPT access and found two suspiciously named files ("Writing is easy.txt" and "I'm a genius.txt") made at 8:52PM and 8:54PM with file sizes too large to have been handwritten in just a couple minutes. The files were found to be written in Notepad.exe.
Query used:
DeviceFileEvents
| where TimeGenerated between (todatetime('2025-10-23T20:40:52.5019101Z') ..todatetime('2025-10-23T20:59:13.4891584Z') )
| where InitiatingProcessFileName in ("notepad.exe", "winword.exe")
| where DeviceName == "threathunting-d"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FileSize, FolderPath

Searched DeviceEvents to corroborate clipboard use with notepad around the same time as the file creation and AI use. Found that Notepad was used with the clipboard at timestamp 2025-10-23T20:52:06.3493213Z or 8:52PM which correlates exactly with the file creation.
Query used:
DeviceEvents
| where DeviceName =="threathunting-d"
| where TimeGenerated between (todatetime('2025-10-23T20:40:52.5019101Z') ..todatetime('2025-10-23T20:59:13.4891584Z') )
| where ActionType == "GetClipboardData"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName



---

## Chronological Events


---

## Summary

...

---

## Response Taken
TOR usage was confirmed on endpoint ______________. The device was isolated and the user's direct manager was notified.

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

## Detection Queries:
```kql
// ChatGPT domain ip address == ("104.18.39.85", "172.64.155.209")
// Detect connection to ChatGPT
DeviceNetworkEvents
| where RemoteIP in ("23.48.203.9", "172.64.155.209")
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
