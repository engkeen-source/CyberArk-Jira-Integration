# CyberArk-Jira-Integration

1. Clone the repository
2. Manually unzip the references.zip
3. Add reference to the current solution
  - CyberArk.PasswordVault.PublicInterfaces.dll
  - Newtonsoft.Json.dll
  - RestSharp.dll
4. Ensure .NET framework is 4.8
5. Build the solution, dll will be located in the debug folder.
6. Copy this dll to PVWA Bin folder.

# Function Implemented
1. Validate ticket based on
  - Ticket's assignee need to match with PVWA user
  - Ticket's status need to match with allowed status configured in PVWA -> Option -> Ticketing System
  - Ticket's start time and end time need to match with PVWA user request time.
  - Ticket's configuration item need to match with requesting machine/remote machine.

2. Create incident ticket to Jira with following parameter
  - This scenario will trigger if user input "Create Incident Ticket" code configured in PVWA -> Option -> Ticketing System
  - Static Parameter
    - requesting machine/remote machine, convert to ticket's configuration item.
    - password object's additional file categories (tower ID), convert to ticket's team name.
    - pvwa user, convert to ticket's assignee

3. Leave a comment to ticket, whenever ticket is validated successfully and user generated a RDP file successfully.
  - Comment will include below parameter 
    - Reason
    - Requesting User
    - Requesting User's email
    - Object's parameter
    - Dual Control
    - Dual Control Request Confirmed.
    - etc
  - This parameter can be configure in the cs file.

4. Logging
  - Log will be generated in PVWA server, file path can be configured  in PVWA -> Option -> Ticketing System

5. Reporting/Overview
  - Csv file will be generated in PVWA server, regarding the ticket validated success/fail, created success/fail.

6. Bypass Jira Validation Check in the event ticketing system is not available.
  - User need to enter bypass code in ticket ID
  - bypass code can be configured in PVWA -> Option -> Ticketing System

# Configurable Item in PVWA

1. Login to PVWA as administrator, go to Option -> Ticketing System and configure below parameter.

allowedChangeTicketStatus

allowedServiceRequestTicketStatus

allowedIncidentTicketStatus

allowedProblemTicketStatus

allowTicketFormatRegex

msgInvalidTicket

msgInvalidTicketFormat

msgInvalidTicketStatus

msgConnectionError

msgInvalidAccessTime

msgInvalidMachine

msgInvalidImplementer

chkLogonToTicketingSystem

enChkTime

enChkCI

enChkImplementer

bypassJiraValidationCode

bypassJiraValidateTimeStampCode

createJiraIncValidationCode

jiraApiKey_CI

jiraApiKey_StartTime

jiraApiKey_EndTime

logFilePath












