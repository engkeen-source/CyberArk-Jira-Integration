using System;
using System.IO;
using System.Xml;
using System.Net;
using System.Text;
using System.Globalization;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using CyberArk.PasswordVault.PublicInterfaces;
using RestSharp;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jira.TicketingValidation{

	#region Public Class - Main
	public class JiraTicketingValidator : ITicketVaildatorEx {

		#region Public Parameters
		//Use TLS 1.2
		public const System.Net.SecurityProtocolType SecurityProtocol = SecurityProtocolType.Tls12;

		//set Ticketing Parameters
		public string checkParameters					= string.Empty;
		public string ticketingID						= string.Empty;
		public string ticketingSys						= string.Empty;
		public string ticketingAssignee					= string.Empty;
		public DateTime ticketStartTime					= new DateTime();
		public DateTime ticketEndTime					= new DateTime();

		//set Info from CyberArk Interface
		public string cybrSafeName						= string.Empty;
		public string cybrObjectName					= string.Empty;
		public string cybrMachineAddress				= string.Empty;
		public string cybrTransparentMachineAddress		= string.Empty;
		public string cybrRequestingUser				= string.Empty;
		public bool cybrDualControl						= false;
		public bool cybrDualControlRequestConfirmed		= false;
		public string cybrReason						= string.Empty;
		public string cybrUsername						= string.Empty;
		public string cybrRequesterName					= string.Empty;
		public string cybrEmail							= string.Empty;
		public string cybrPolicy						= string.Empty;
		public string cybrTower							= string.Empty;
		public string cybrHostname						= string.Empty;
		public string cybrDatabase						= string.Empty;
		public string cybrPort							= string.Empty;

		//set api logon
		public bool chkLogonToTicketingSystem			= false;
		public string jiralogonAddress					= string.Empty;
		public string jiralogonUsername					= string.Empty;
		public string jiralogonPassword					= string.Empty;

		//set error messages
		public string msgInvalidTicket					= string.Empty;
		public string msgInvalidTicketFormat			= string.Empty;
		public string msgInvalidTicketStatus			= string.Empty;
		public string msgInvalidMachine					= string.Empty;
		public string msgInvalidAccessTime				= string.Empty;
		public string msgInvalidImplementer				= string.Empty;
		public string msgConnectionError				= string.Empty;

		//set bypass ticket code
		public string bypassJiraValidationCode			= string.Empty;
		public string bypassJiraValidateTimeStampCode	= string.Empty;

		//set create ticket code;
		public string createJiraIncValidationCode		= string.Empty;

		//set allowed Ticket Status
		public string allowedChangeTicketStatus			= string.Empty;
		public string allowedServiceRequestTicketStatus = string.Empty;
		public string allowedIncidentTicketStatus		= string.Empty;
		public string allowedProblemTicketStatus		= string.Empty;

		//set allowTicketFormatRegex
		public string allowTicketFormatRegex			= string.Empty;

		//set check condition bool
		public bool enChkCI								= true;
		public bool enChkTime							= true;
		public bool enChkImplementer					= true;

		//set jira api response key
		public string jiraApiKey_CI						= string.Empty;
		public string jiraApiKey_StartTime				= string.Empty;
		public string jiraApiKey_EndTime				= string.Empty;

		//internal paramater
		public string logMessage						= string.Empty;
		public string errorMessage						= string.Empty;
		public string auditMessage						= string.Empty;

		//CMDB configItemID
		public string configItemID						= string.Empty;

		//EmergencyMode
		public bool emergencyMode						= false;
		public bool bypassValidateTimeMode				= false;

		//Logging
		public string logFilePath						= string.Empty;
		#endregion

		#region Public Function ValidateTicket
		public bool ValidateTicket(IValidationParametersEx parameters, out ITicketOutput ticketingOutput) {
			#region Init/Declare
			// Validation result (the return value) - will contain true if validate succeed, false otherwise
			bool bValid = false;

			//Set ticketing output
			ticketingOutput = new TicketOutput();

			// Kept the default ParseXML input & output.But parameters are parse to the public variables
			ParseXmlParameters(parameters.XmlNodeParameters);

			//Fetch Service accout
			ITicketingConnectionAccount connectionAccount		= parameters.TicketingConnectionAccount;

			//Fetch from PVWA
			cybrSafeName										= parameters.SafeName;
			cybrObjectName										= parameters.ObjectName;
			cybrMachineAddress									= parameters.MachineAddress.Trim().ToUpper();
			cybrTransparentMachineAddress						= parameters.TransparentMachineAddress.Trim().ToUpper();
			cybrDualControl										= parameters.DualControl;
			cybrDualControlRequestConfirmed						= parameters.DualControlRequestConfirmed;
			cybrReason											= parameters.ProvidedReason;
			cybrUsername										= parameters.UserName;
			cybrRequesterName									= parameters.RequestingUserFirstName + " " + parameters.RequestingUserSurname;
			cybrEmail											= parameters.RequestingUserEmail;
			cybrPolicy											= parameters.PolicyId;
			//Additinal Parameter
			if (parameters.AdditionalProperties.ContainsKey("Tower"))
			{
				cybrTower										= parameters.AdditionalProperties["Tower"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Hostname"))
			{
				cybrHostname									= parameters.AdditionalProperties["Hostname"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Database"))
			{
				cybrHostname									= parameters.AdditionalProperties["Database"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Port"))
			{
				cybrHostname									= parameters.AdditionalProperties["Port"];
			}


			//Set User info
			cybrRequestingUser									= parameters.RequestingUser.Trim().ToUpper();

			//set ticketing parameter
			ticketingSys										= parameters.SystemName.ToUpper();
			ticketingID											= parameters.TicketId.Trim().ToUpper();

			//Set API Logon Parameters
			jiralogonAddress									= parameters.TicketingConnectionAccount.Address;
			jiralogonUsername									= parameters.TicketingConnectionAccount.UserName;
			jiralogonPassword									= parameters.TicketingConnectionAccount.Password;

			//Audit
			auditMessage = string.Format("Input={0} | DualControl={1} | DualControlRequestConfirmed={2} |", ticketingID, cybrDualControl, cybrDualControlRequestConfirmed);

			#endregion

			#region Log
			LogWrite("Initializing process ...");
			LogWrite("Fetched XML parameter");
			LogWrite(string.Format("{0}: {1}", "allowedChangeTicketStatus"				, allowedChangeTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedServiceRequestTicketStatus"		, allowedServiceRequestTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedIncidentTicketStatus"			, allowedIncidentTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedProblemTicketStatus"				, allowedProblemTicketStatus));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicket"						, msgInvalidTicket));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicketFormat"					, msgInvalidTicketFormat));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicketStatus"					, msgInvalidTicketStatus));
			LogWrite(string.Format("{0}: {1}", "msgConnectionError"						, msgConnectionError));
			LogWrite(string.Format("{0}: {1}", "msgInvalidAccessTime"					, msgInvalidAccessTime));
			LogWrite(string.Format("{0}: {1}", "msgInvalidMachine"						, msgInvalidMachine));
			LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer"					, msgInvalidImplementer));
			LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer"					, chkLogonToTicketingSystem));
			LogWrite(string.Format("{0}: {1}", "enChkTime"								, enChkTime));
			LogWrite(string.Format("{0}: {1}", "enChkCI"								, enChkCI));
			LogWrite(string.Format("{0}: {1}", "enChkImplementer"						, enChkImplementer));
			LogWrite(string.Format("{0}: {1}", "bypassJiraValidationCode"				, bypassJiraValidationCode));
			LogWrite(string.Format("{0}: {1}", "createJiraIncValidationCode"			, createJiraIncValidationCode));
			LogWrite("Fetched connecting account to " + ticketingSys);
			LogWrite(string.Format("{0}: {1}", "jiralogonAddress"						, jiralogonAddress));
			LogWrite(string.Format("{0}: {1}", "jiralogonUsername"						, jiralogonUsername));
			LogWrite(string.Format("{0}: {1}", "Jira Object Name"						, parameters.TicketingConnectionAccount.ObjectName));
			LogWrite(string.Format("{0}: {1}", "Jira Safe Name"							, parameters.TicketingConnectionAccount.Safe));
			LogWrite(string.Format("{0}: {1}", "Jira Folder Name"						, parameters.TicketingConnectionAccount.Folder));
			LogWrite("Fetched connecting account to " + ticketingSys + " -> Additional Properties");
			foreach (var item in parameters.TicketingConnectionAccount.Properties)
			{
				LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
			}

			LogWrite("Fetched ticketing parameter.");
			LogWrite(string.Format("{0}: {1}", "TicketId"								, parameters.TicketId));
			LogWrite(string.Format("{0}: {1}", "SafeName"								, parameters.SafeName));
			LogWrite(string.Format("{0}: {1}", "FolderName"								, parameters.FolderName));
			LogWrite(string.Format("{0}: {1}", "ObjectName"								, parameters.ObjectName));
			LogWrite(string.Format("{0}: {1}", "MachineAddress"							, parameters.MachineAddress));
			LogWrite(string.Format("{0}: {1}", "TransparentMachineAddress"				, parameters.TransparentMachineAddress));
			LogWrite(string.Format("{0}: {1}", "UserName"								, parameters.UserName));
			LogWrite(string.Format("{0}: {1}", "PolicyId"								, parameters.PolicyId));
			LogWrite(string.Format("{0}: {1}", "RequestingUser"							, parameters.RequestingUser));
			LogWrite(string.Format("{0}: {1}", "RequestingUserFirstName"				, parameters.RequestingUserFirstName));
			LogWrite(string.Format("{0}: {1}", "RequestingUserSurName"					, parameters.RequestingUserSurname));
			LogWrite(string.Format("{0}: {1}", "BusinessEmail"							, parameters.RequestingUserEmail));
			LogWrite(string.Format("{0}: {1}", "ProvidedReason"							, parameters.ProvidedReason));
			LogWrite(string.Format("{0}: {1}", "SystemName"								, parameters.SystemName));
			LogWrite(string.Format("{0}: {1}", "DualControl"							, parameters.DualControl));
			LogWrite(string.Format("{0}: {1}", "DualControlRequestConfirmed"			, parameters.DualControlRequestConfirmed));

			LogWrite("Fetched ticketing parameter -> Additonal Properties");
			foreach (var item in parameters.AdditionalProperties)
			{
				if (item.Key == "LastFailDate")
				{
					LogWrite(string.Format("{0}: {1}", item.Key, UnixTimeStampToDateTime(item.Value)));
				}
				else
				{
					LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
				}
				
			}
			#endregion

			#region Create Ticket
			//if matching createINC by pass code, create inc ticket
			LogWrite("Checking to create ticket...");
			if (IsValueEmpty(createJiraIncValidationCode) == false)
			{
				bool ChCreateInc = Regex.IsMatch(ticketingID, createJiraIncValidationCode.Trim().ToUpper());
				if (ChCreateInc == true)
				{
					LogWrite("Entering Function CreateTicketIdUsingTicketingSystem()");
					ticketingID = CreateTicketIdUsingTicketingSystem();
					if (string.IsNullOrEmpty(ticketingID) == false)
					{
						ticketingOutput.TicketId = ticketingID;
						ticketingOutput.TicketAuditOutput = " " + auditMessage + ticketingID + " created successfully.";
						LogWrite("TicketId: " + ticketingID);
						LogWrite(ticketingOutput.TicketAuditOutput);
						CsvWrite(ticketingID, "Created Successfully");
						LogWrite("Process ended...");
						return true;
					}
					if (string.IsNullOrEmpty(ticketingID) == true)
					{
						ticketingOutput.UserMessage = errorMessage + " TicketID failed to create.";
						ticketingOutput.TicketAuditOutput = auditMessage + " TicketID failed to create.";
						LogWrite(ticketingOutput.UserMessage);
						LogWrite(ticketingOutput.TicketAuditOutput);
						CsvWrite("", "Failed to Create");
						LogWrite("Process ended...");
						return false;
					}
				}
			}
			#endregion

			#region Validate Ticket

			#region check emergencyMode
			//if matching bypass code, return true
			LogWrite("Checking to validate ticket...");
			LogWrite("Checking TicketID matched BypassID...");
			if (IsValueEmpty(bypassJiraValidationCode) == false)
			{
				emergencyMode = Regex.IsMatch(ticketingID, bypassJiraValidationCode);
				auditMessage += " Emergency=" + emergencyMode + " | ";
				if (emergencyMode == true)
				{
					auditMessage += "Ticket validated successfully.";
					ticketingOutput.TicketAuditOutput = string.Format("{0},{1}", ticketingID, auditMessage);
					LogWrite(ticketingOutput.TicketAuditOutput);
					CsvWrite(ticketingID, "Validated Successfully");
					LogWrite("Process ended...");
					return true;
				}
			}
			#endregion

			#region check ticket format
			//if ticket format is incorrect, return false
			LogWrite("Checking TicketID is in correct format...");
			if (IsValueEmpty(allowTicketFormatRegex) == false)
			{
				bool ChTicketFormatResult = Regex.IsMatch(ticketingID, allowTicketFormatRegex);
				if (ChTicketFormatResult == false)
				{
					errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicketFormat);
					ticketingOutput.UserMessage = errorMessage;
					LogWrite(ticketingOutput.UserMessage);
					CsvWrite(ticketingID, "Failed to validate");
					LogWrite("Process ended...");
					return bValid;
				}
			}
			#endregion

			#region check connection to Jira
			if (connectionAccount != null)
			{
				if (chkLogonToTicketingSystem == true) 
				{
					bool isConnectedToJira = LogonToTicketingSystem(jiralogonAddress, jiralogonUsername, jiralogonPassword);
					LogWrite("Checking connectivity to Jira, Address=" + jiralogonAddress);
					if (isConnectedToJira == false)
					{
						errorMessage = msgConnectionError + " You can enter bypass code in ticket ID.";
						ticketingOutput.UserMessage = errorMessage;
						LogWrite(errorMessage);
						LogWrite("Process ended...");
						return bValid;
					}
					LogWrite("Successfully logon to Jira: " + isConnectedToJira);
				}
			}
			if (connectionAccount == null) {
				ticketingOutput.UserMessage = "No ticketing system login account was specified";
				LogWrite(ticketingOutput.UserMessage);
				LogWrite("Process ended...");
				return bValid;
			}
			#endregion

			#region check ticket validity
			LogWrite("Checking TicketID validity...");
			bValid = CheckTicketIdValidity(ticketingID);
			#endregion

			#region post-validation
			if (bValid == false)
			{
				auditMessage += " TicketID validation failed.";
				ticketingOutput.UserMessage = errorMessage;
				ticketingOutput.TicketAuditOutput = auditMessage;
				LogWrite("Error: " + errorMessage);
				LogWrite("Audit: " + auditMessage);
				CsvWrite(ticketingID, "Failed to Validate");
			}
			if (bValid == true)
			{
				auditMessage += " TicketID validated successfully.";
				ticketingOutput.TicketId = ticketingID;
				ticketingOutput.TicketAuditOutput = auditMessage;
				if (ticketStartTime != DateTime.MinValue && ticketEndTime != DateTime.MinValue)
				{
					ticketingOutput.RequestStartDate = ticketStartTime;
					ticketingOutput.RequestEndDate = ticketEndTime;
				}
				LogWrite("TicketId: " + ticketingID);
				LogWrite("Audit: " + auditMessage);
				CsvWrite(ticketingID, "Validated Successfully");

				//Comment on Jira - leave a record
				LogWrite("Writing comment on TicketID: " + ticketingID);
				var comment = new JiraComment();
				comment.AddCommentLine("Reason: " + cybrReason);
				comment.AddCommentLine("Requesting User: " + cybrRequesterName);
				comment.AddCommentLine("Requesting User ADID: " + cybrRequestingUser);
				comment.AddCommentLine("Requesting User Email: " + cybrEmail);
				comment.AddCommentLine("Device Address: " + GetConnectionAddress());
				comment.AddCommentLine("Safe: " + cybrSafeName);
				comment.AddCommentLine("Object: " + cybrObjectName);
				comment.AddCommentLine("Account: " + cybrUsername);
				comment.AddCommentLine("Policy: " + cybrPolicy);
				//Additional Parameter
				OutputToCommentIfNotEmpty(comment, "Hostname", cybrHostname);
				OutputToCommentIfNotEmpty(comment, "Database", cybrDatabase);
				OutputToCommentIfNotEmpty(comment, "Port", cybrPort);
				OutputToCommentIfNotEmpty(comment, "Dual Control", cybrDualControl.ToString());
				OutputToCommentIfNotEmpty(comment, "Dual Control Request Confirmed", cybrDualControlRequestConfirmed.ToString());

				//Call Api to Jira
				var CommentToJira = new JiraApi()
				{
					url = "https://" + jiralogonAddress + "/rest/api/2/issue/" + ticketingID + "/comment",
					method = "post",
					username = jiralogonUsername,
					password = jiralogonPassword,
					body = JsonConvert.SerializeObject(comment)
				};
				var IsCommentSuccessul = CommentToJira.Call().IsSuccessful;
				LogWrite(string.Format("Comment On TicketID: {0} Status: {1}", ticketingID, IsCommentSuccessul));
			}
			#endregion

			LogWrite("Process ended...");
			return bValid;
			#endregion
		}

		//If value not empty, write to comment object
		private void OutputToCommentIfNotEmpty(JiraComment comment, string key, string value)
		{
			if (string.IsNullOrEmpty(value) == false)
			{
				comment.AddCommentLine(string.Format("{0}: {1}", key, value));
			}
		}

		//Convert Unix Tiem Stamp to DateTime
		private static string UnixTimeStampToDateTime(string unixTimeStamp)
		{
			//Convert string to Double
			Double.TryParse(unixTimeStamp, out double unixTimeStampDouble);

			// Unix timestamp is seconds past epoch
			DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
			dateTime = dateTime.AddSeconds(unixTimeStampDouble).ToLocalTime();
			return dateTime.ToString();
		}

		#endregion

		#region Private Function CreateTicketIdUsingTicketingSystem - return ticket ID if ticket successfully created, else return null
		private string CreateTicketIdUsingTicketingSystem() {

			LogWrite("Entered CreateTicketIdUsingTicketingSystem()");
			//If there is no tower, cannot create incident ticket.
			if (string.IsNullOrEmpty(cybrTower) == true)
			{
				errorMessage += " You are not authorized to create Incident ticket in PAM Portal. Please check with PAM Team.";
				return null;
			}

			//Get address
			string address = GetConnectionAddress();
			LogWrite("address: " + address);

			//Query Cmdb
			LogWrite("Querying Cmdb...");
			var json = new CmdbQuery(address);
			var QueryToCmbd = new JiraApi()
			{
				url = "https://" + jiralogonAddress + "/rest/insight/1.0/object/navlist/iql",
				method = "post",
				username = jiralogonUsername,
				password = jiralogonPassword,
				body = JsonConvert.SerializeObject(json)
			};
			var CmdbResponse = new CmdbQueryResponse(QueryToCmbd.Call());

			//Get ConfigItemId
			configItemID = CmdbResponse.ConfigItem_ID;
			LogWrite("configItemID: " + configItemID);
			if (string.IsNullOrEmpty(configItemID) == true)
			{
				errorMessage += "Failed to get server ID from CMDB.";
				return null;
			}

			//Create Incident Ticket Object
			LogWrite("Creating Incident ticket...");
			var incidentTicket = new Ticket("INC");

			//Incident ticket properties
			incidentTicket.AddReason(cybrReason);
			incidentTicket.AddAssignee(cybrRequestingUser);
			incidentTicket.AddCI(configItemID);
			incidentTicket.AddTower(cybrTower);
			incidentTicket.AppendDescription("Requesting User: " + cybrRequesterName);
			incidentTicket.AppendDescription("Requesting User ADID: " + cybrRequestingUser);
			incidentTicket.AppendDescription("Requesting User Email: " + cybrEmail);
			incidentTicket.AppendDescription("Device Address: " + address);
			incidentTicket.AppendDescription("Safe: " + cybrSafeName);
			incidentTicket.AppendDescription("Object: " + cybrObjectName);
			incidentTicket.AppendDescription("Account: " + cybrUsername);
			incidentTicket.AppendDescription("Policy: " + cybrPolicy);
			OutputToIncDescIfNotEmpty(incidentTicket, "Hostname", cybrHostname);
			OutputToIncDescIfNotEmpty(incidentTicket, "Database", cybrDatabase);
			OutputToIncDescIfNotEmpty(incidentTicket, "Port", cybrPort);
			OutputToIncDescIfNotEmpty(incidentTicket, "Dual Control", cybrDualControl.ToString());
			OutputToIncDescIfNotEmpty(incidentTicket, "Dual Control Request Confirmed", cybrDualControlRequestConfirmed.ToString());

			//Send to Jira
			LogWrite("Sending Api to Jira...");
			var LogonToJira = new JiraApi()
			{
				url = "https://" + jiralogonAddress + "/rest/api/2/issue/",
				method = "post",
				username = jiralogonUsername,
				password = jiralogonPassword,
				body = JsonConvert.SerializeObject(incidentTicket)
			};
			var response = LogonToJira.Call();

			//Capture response
			var responseHandle = new JiraCreateTicketResponse(response);

			//Get ticketID
			if (responseHandle.StatusCode == 201)
			{
				return responseHandle.GetTicketID();
			}
			else
			{
				errorMessage = "API response status code is not 201(created). " + responseHandle.GetError();
				return null;
			}
		}

		//If value not empty, write to comment object
		private void OutputToIncDescIfNotEmpty(Ticket incidentTicket, string key, string value)
		{
			if (string.IsNullOrEmpty(value) == false)
			{
				incidentTicket.AppendDescription(string.Format("{0}: {1}", key, value));
			}
		}
		#endregion

		#region Private Function CheckTicketIdValidity - return TRUE if ticket is valid
		private bool CheckTicketIdValidity(string ticketID)
		{
			LogWrite("Entered CheckTicketIdValidity()");
			
			//Declare
			bool ChkCIResult			= false;
			bool ChkTimeResult			= false;
			bool ChkImplementerResult	= false;
			bool ChkCurrentTicketStatus	= false;

			//Checking bypassValidateTimeMode;
			bypassValidateTimeMode		= ticketID.Contains(bypassJiraValidateTimeStampCode);
			if (bypassValidateTimeMode == true)
			{
				enChkTime				= false;
				auditMessage			+= " bypassValidateTimeMode= " + bypassValidateTimeMode + " | ";

				//Extract TicketID
				ticketID				= ticketID.Replace(bypassJiraValidateTimeStampCode, "").Trim();
			}
			LogWrite("bypassValidateTimeMode: " + bypassValidateTimeMode);
			LogWrite("enChkTime: "				+ enChkTime);


			//Ticket Type - SCR/NCR/ECR/ISR/SR/INC/PR
			string ticketType			= ticketID.Split('-')[0].Trim().ToUpper();
			string ticketCategory		= string.Empty;
			switch (ticketType)
			{
				case "SCR":
					ticketCategory		= "CR";
					break;
				case "NCR":
					ticketCategory		= "CR";
					break;
				case "ECR":
					ticketCategory		= "CR";
					break;
				case "SR":
					ticketCategory		= "SR";
					break;
				case "ISR":
					ticketCategory		= "SR";
					break;
				case "INC":
					ticketCategory		= "INC";
					break;
				case "PR":
					ticketCategory		= "PR";
					break;

			}

			LogWrite("Sending Api to Jira");
			var QueryToJira = new JiraApi()
			{
				url = "https://" + jiralogonAddress + "/rest/api/2/issue/" + ticketID,
				method = "get",
				username = jiralogonUsername,
				password = jiralogonPassword
			};

			var response = QueryToJira.Call();

			//Valid Ticket
			if (response.IsSuccessful == true)
			{
				var JiraQuery = new JiraQueryResponse(response);

				switch (ticketCategory)
				{
					case "CR":
						ChkTimeResult			= ValidateTime(JiraQuery);
						ChkCIResult				= ValidateCI(JiraQuery);
						ChkImplementerResult	= ValidateAssignee(JiraQuery);
						ChkCurrentTicketStatus	= ValidateTicketStatus(JiraQuery, ticketCategory);
						break;

					case "SR":
						ChkTimeResult			= true;
						ChkCIResult				= true;
						ChkImplementerResult	= ValidateAssignee(JiraQuery);
						ChkCurrentTicketStatus	= ValidateTicketStatus(JiraQuery, ticketCategory);
						break;

					case "INC":
						ChkTimeResult			= true;
						ChkCIResult				= true;
						ChkImplementerResult	= ValidateAssignee(JiraQuery);
						ChkCurrentTicketStatus	= ValidateTicketStatus(JiraQuery, ticketCategory);
						break;

					case "PR":
						ChkTimeResult			= true;
						ChkCIResult				= true;
						ChkImplementerResult	= ValidateAssignee(JiraQuery);
						ChkCurrentTicketStatus	= ValidateTicketStatus(JiraQuery, ticketCategory);
						break;
				}

				return (ChkTimeResult && ChkCIResult && ChkImplementerResult && ChkCurrentTicketStatus);
			}

			//Invalid Ticket
			if (response.IsSuccessful == false)
			{
				errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicket);
				return false;
			}

			errorMessage = "Exception occurred. Please check with PAM Administrator.";
			return false;
		}

		private bool ValidateTime(JiraQueryResponse jiraQuery)
		{
			bool result = false;

			if (enChkTime == false)
			{
				return true;
			}
			if (enChkTime == true)
			{
				if (string.IsNullOrEmpty(jiraApiKey_StartTime) == false && string.IsNullOrEmpty(jiraApiKey_EndTime) == false)
				{
					LogWrite("Checking ticket time Validity...");

					//Get StartTime, EndTime
					string strStartTime		= jiraQuery.GetCustomField(jiraApiKey_StartTime);
					string strEndTime		= jiraQuery.GetCustomField(jiraApiKey_EndTime);
					result					= Timecheck(strStartTime, strEndTime);
					LogWrite("Ticket Start Time: " + ticketStartTime);
					LogWrite("Ticket End Time: " + ticketEndTime);
					if (result == false)
					{
						errorMessage = string.Format("[{0} - {1}] Access only allowed from {2} to {3}.", ticketingSys, ticketingID, ticketStartTime, ticketEndTime);
					}
				}
				else
				{
					errorMessage = string.Format("jiraApiKey_StartTime or jiraApiKey_EndTime is null. Please check PAM Option.");
				}
			}

			return result;
		}

		private bool ValidateCI(JiraQueryResponse jiraQuery)
		{
			bool result = false;

			if (enChkCI == false)
			{
				return true;
			}
			string deviceAddress = string.Empty;
			if (enChkCI == true)
			{
				string connectionAddress = GetConnectionAddress();
				LogWrite("connectionAddress: " + connectionAddress);

				if (string.IsNullOrEmpty(jiraApiKey_CI) == true)
				{
					errorMessage = string.Format("jiraApiKey_CI is null. Please check PAM Option.");
					return false;
				}

				//Query Cmdb
				var json = new CmdbQuery(connectionAddress);
				var QueryToCmbd = new JiraApi()
				{
					url = "https://" + jiralogonAddress + "/rest/insight/1.0/object/navlist/iql",
					method = "post",
					username = jiralogonUsername,
					password = jiralogonPassword,
					body = JsonConvert.SerializeObject(json)
				};
				var CmdbResponse = new CmdbQueryResponse(QueryToCmbd.Call());

				//Get ConfigItemId
				configItemID = CmdbResponse.ConfigItem_ID;
				LogWrite("configItemID: " + configItemID);

				//Validate Ticket CI
				result = jiraQuery.ValidateCI(configItemID, jiraApiKey_CI);

				if (result == false)
				{
					errorMessage = string.Format("[{0} - {1}] Machine {2} is not part of ticket's configuration items.", ticketingSys, ticketingID, cybrTransparentMachineAddress);
				}
			}

			return result;
		}

		private bool ValidateAssignee(JiraQueryResponse jiraQuery)
		{
			bool result = false;

			if (enChkImplementer == false)
			{
				return true;
			}
			if (enChkImplementer == true)
			{
				//Get assignee
				string strAssignee = jiraQuery.GetAssignee();
				LogWrite("Ticket Assignee: " + strAssignee);
				if (strAssignee == null)
				{
					errorMessage = string.Format("[{0} - {1}] {2} is not ticket's assignee", ticketingSys, ticketingID, cybrRequestingUser.ToLower());
					return false;
				}

				result = strAssignee.Trim().ToUpper() == cybrRequestingUser;

				if (result == true)
				{
					auditMessage += "TicketAssignee= " + strAssignee + " | ";
				}

				if (result == false)
				{
					errorMessage = string.Format("[{0} - {1}] No assignee in assigned ticket.", ticketingSys, ticketingID);
				}
			}

			return result;
		}

		private bool ValidateTicketStatus(JiraQueryResponse jiraQuery, string TicketCategory)
		{
			string allowedTicketStatus	= string.Empty;
			bool result					= false;

			switch (TicketCategory)
			{
				case "CR":
					allowedTicketStatus = allowedChangeTicketStatus;
					break;

				case "SR":
					allowedTicketStatus = allowedServiceRequestTicketStatus;
					break;

				case "INC":
					allowedTicketStatus = allowedIncidentTicketStatus;
					break;

				case "PR":
					allowedTicketStatus = allowedProblemTicketStatus;
					break;
			}

			if (IsValueEmpty(allowedTicketStatus) == true)
			{
				errorMessage += "allowTicketStatus is null. Please contact PAM administrator.";
				return false;
			}

			//Validate status
			string strCurrentTicketStatus = jiraQuery.GetStatus();
			LogWrite("Ticket Status: " + strCurrentTicketStatus);
			result = Regex.IsMatch(strCurrentTicketStatus, allowedTicketStatus);
			if (result == false)
			{
				errorMessage = string.Format("[{0} - {1}] Current ticket Status: {2}, Allow Ticket Status: {3}", ticketingSys, ticketingID, strCurrentTicketStatus, allowedTicketStatus);
			}

			return result;

		}

		private string GetConnectionAddress()
		{
			if (cybrTransparentMachineAddress != null)
			{
				return cybrTransparentMachineAddress;
			}

			if (cybrMachineAddress != null)
			{
				return cybrMachineAddress;
			}
			return null;
		}

		private bool Timecheck(string timeStart, string timeEnd){

			if (timeStart == null || timeEnd == null)
			{
				errorMessage = "Start time or end time cannot be null.";
				return false;
			}

			//Sample Return From RestSharp - 01/26/2021 13:00:00 - String
			int yearStart	= int.Parse(timeStart.Substring(6, 4));
			int yearEnd		= int.Parse(timeEnd.Substring(6, 4));
			int monthStart	= int.Parse(timeStart.Substring(0, 2));
			int monthEnd	= int.Parse(timeEnd.Substring(0, 2));
			int dayStart	= int.Parse(timeStart.Substring(3, 2));
			int dayEnd		= int.Parse(timeEnd.Substring(3, 2));
			int hourStart	= int.Parse(timeStart.Substring(11, 2));
			int hourEnd		= int.Parse(timeEnd.Substring(11, 2));
			int minStart	= int.Parse(timeStart.Substring(14, 2));
			int minEnd		= int.Parse(timeEnd.Substring(14, 2));
			int secStart	= int.Parse(timeStart.Substring(17, 2));
			int secEnd		= int.Parse(timeEnd.Substring(17, 2));

			ticketStartTime = new DateTime(yearStart, monthStart, dayStart, hourStart, minStart, secStart);
			ticketEndTime = new DateTime(yearEnd, monthEnd, dayEnd, hourEnd, minEnd, secEnd);
			DateTime now = DateTime.Now;

			return ((now > ticketStartTime) && (now < ticketEndTime));
		}

		#endregion

		#region Private Function LogonToTicketingSystem - return TRUE if able to connect to Ticketing System
		private bool LogonToTicketingSystem(string ticketingSystemAddress, string ticketingSystemUsername, string ticketingSystemPassword){

			var LogonToJira = new JiraApi()
			{
				url = "https://" + ticketingSystemAddress,
				method = "get",
				username = ticketingSystemUsername,
				password = ticketingSystemPassword
			};

			var response = LogonToJira.Call();

			if (response.IsSuccessful)
			{
				return true;
			}

			errorMessage = errorMessage + " " + msgConnectionError + " " + "Unable to connect to " + ticketingSystemAddress + " ";
			return false;
		}
		#endregion

		#region Private Function ParseXmlParameters - Capture Ticketing Parameters from PVConfig.xml
		private void ParseXmlParameters(XmlNode xmlParameters){
			//Fetch ticketing parameters from PVWA
			checkParameters = xmlParameters.InnerXml;

			//Allow Ticket Status
			allowedChangeTicketStatus			= ExtractValueFromXML(checkParameters, "allowedChangeTicketStatus");
			allowedServiceRequestTicketStatus	= ExtractValueFromXML(checkParameters, "allowedServiceRequestTicketStatus");
			allowedIncidentTicketStatus			= ExtractValueFromXML(checkParameters, "allowedIncidentTicketStatus");
			allowedProblemTicketStatus			= ExtractValueFromXML(checkParameters, "allowedProblemTicketStatus");

			//Allow Ticket Format Regex
			allowTicketFormatRegex				= ExtractValueFromXML(checkParameters, "allowTicketFormatRegex");

			//Error Message
			msgInvalidTicket					= ExtractValueFromXML(checkParameters, "msgInvalidTicket");
			msgInvalidTicketFormat				= ExtractValueFromXML(checkParameters, "msgInvalidTicketFormat");
			msgInvalidTicketStatus				= ExtractValueFromXML(checkParameters, "msgInvalidTicketStatus");
			msgConnectionError					= ExtractValueFromXML(checkParameters, "msgConnectionError");
			msgInvalidAccessTime				= ExtractValueFromXML(checkParameters, "msgInvalidAccessTime");
			msgInvalidMachine					= ExtractValueFromXML(checkParameters, "msgInvalidMachine");
			msgInvalidImplementer				= ExtractValueFromXML(checkParameters, "msgInvalidImplementer");

			//chkLogonToTicketingSystem
			chkLogonToTicketingSystem			= ConvertToBool(ExtractValueFromXML(checkParameters, "chkLogonToTicketingSystem"));

			//validateJiraTimeStamp
			enChkTime							= ConvertToBool(ExtractValueFromXML(checkParameters, "validateJiraTimeStamp"));

			//validateJiraCI
			enChkCI								= ConvertToBool(ExtractValueFromXML(checkParameters, "validateJiraCI"));

			//validateJiraImplementer
			enChkImplementer					= ConvertToBool(ExtractValueFromXML(checkParameters, "validateJiraImplementer"));

			//bypass code
			bypassJiraValidationCode			= ExtractValueFromXML(checkParameters, "bypassJiraValidationCode").Trim().ToUpper();
			bypassJiraValidateTimeStampCode		= ExtractValueFromXML(checkParameters, "bypassJiraValidateTimeStampCode").Trim().ToUpper();

			//create ticket code
			createJiraIncValidationCode			= ExtractValueFromXML(checkParameters, "createJiraIncValidationCode").Trim().ToUpper();

			//jira json key
			jiraApiKey_CI						= ExtractValueFromXML(checkParameters, "jiraJsonKey_CI");
			jiraApiKey_StartTime				= ExtractValueFromXML(checkParameters, "jiraJsonKey_StartTime");
			jiraApiKey_EndTime					= ExtractValueFromXML(checkParameters, "jiraJsonKey_EndTime");

			//log
			logFilePath							= ExtractValueFromXML(checkParameters, "logFilePath");
		}

		private string ExtractValueFromXML(string checkParameters, string lookupValue){
			string regexPattern = lookupValue + "\"" + " Value=\"(.*?)\"";
			Match strMatch = Regex.Match(checkParameters, regexPattern);
			string strResult = strMatch.Groups[1].Value.Trim();
			return strResult;
		}

		private bool ConvertToBool(string strParameter){
			if (strParameter.Length > 0){
				if (strParameter.Trim().ToLower().Equals("yes")){
					return true;
				}

				if (strParameter.Trim().ToLower().Equals("no")){
					return false;
				}
			}

			return false;
		}

		private bool IsValueEmpty(string value)
		{
			return string.IsNullOrEmpty(value);
		}

		//ValidateTicket - Obsolete Function  - Do not Remove - for backward compatibility only
		public bool ValidateTicket(IValidationParameters parameters, out string returnedMessage, out string returnedTicketId)
		{
			throw new NotImplementedException("Obsolete");
		}

		#endregion

		#region Private Function Log/Reporting
		private void LogWrite(string message)
		{
			//FilePath
			var logDirectory = Path.Combine(logFilePath, "Logs");
			if (Directory.Exists(logDirectory) == false)
				Directory.CreateDirectory(logDirectory);

			//FileName
			TextInfo myTI = new CultureInfo("en-US", false).TextInfo;

			var strToday = DateTime.Now.ToString("dd-MM-yyyy");
			var strUser = cybrRequestingUser.ToLower();
			var strName = myTI.ToTitleCase(cybrRequesterName);
			var strTicketingSys = myTI.ToTitleCase(ticketingSys);
			var strTime = strToday + " " + "[ " + DateTime.Now.ToString("hh:mm:ss tt - fffff") + " ]";

			var fileName = strTicketingSys + "_" + strUser + "_" + strName + "_" + strToday + ".log";
			
			var logFile = Path.Combine(logDirectory, fileName);

			var messageToAppend = strTime + " - " + message + Environment.NewLine;

			//Append Message
			File.AppendAllText(logFile, messageToAppend);
		}

		private void CsvWrite(string TicketID, string ValidationStatus)
		{
			//FilePath
			if (Directory.Exists(logFilePath) == false)
				Directory.CreateDirectory(logFilePath);

			//FileName
			var strMonthYear = DateTime.Now.ToString("Y");
			var csvFileName = "Statistic_" + strMonthYear + ".csv";
			var csvFile = Path.Combine(logFilePath, csvFileName);

			//File Exist
			if (File.Exists(csvFile) == false)
			{
				//TicketID, Validation Status, Reason, Safe, Object, Policy
				//Connection Address, Account, User, FirstName, Email
				//Dual Control, Dual Control Request Confirmed, emergencyMode
				var header = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15}"
					, "Date" , "Ticketing System" , "TicketID" , "Validation Status" 
					, "Provided Reason" , "Safe" , "Object" , "Policy"
					, "Connection Address" , "Account" , "User" , "FirstName" , "Email"
					, "Dual Control" , "Dual Control Request Confirmed" , "Emergency Mode");
				header += Environment.NewLine;
				File.AppendAllText(csvFile, header);
			}

			//Append Message
			var messageToAppend = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15}"
					, DateTime.Now.ToString() ,ticketingSys , TicketID , ValidationStatus 
					, cybrReason.Replace(",","|") , cybrSafeName , cybrObjectName , cybrPolicy
					, GetConnectionAddress() , cybrUsername , cybrRequestingUser , cybrRequesterName , cybrEmail
					, cybrDualControl.ToString() , cybrDualControlRequestConfirmed.ToString(), emergencyMode.ToString());
			messageToAppend += Environment.NewLine;
			File.AppendAllText(csvFile, messageToAppend);
		}

		#endregion
	}

	#endregion

	#region Public Class - to contrust json body to create Jira Ticket
	//Reference - https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples/

	public class Ticket
	{
		public Fields fields { get; set; }
		public Ticket(string ticketType)
		{
			fields = new Fields()
			{
				description = "Ticket created by PAM Web portal.",

				//service desk
				issuetype = new Dictionary<string, string> { { "id", "10005" } },
				customfield_10001 = "inc/1c62b287-075b-45b1-bdd6-f80394d05424",

				//configuration items
				customfield_11105 = new List<ConfigItems>(),

				//assigned tower
				customfield_11800 = new List<Dictionary<string, string>>(),

				//assignee
				assignee = new NameItems()
			};

			//set ticket type
			if (ticketType.Trim().ToUpper() == "INC")
			{
				fields.project = new Dictionary<string, string> { { "key", "INC" } };
			}
		}

		//add string to summary
		public void AddReason(string reason)
		{
			fields.summary = reason;
		}

		//add CI to customfield_11105
		public void AddCI(string CI)
		{
			var item = new ConfigItems();
			item.key = CI;
			fields.customfield_11105.Add(item);
		}

		//add assigned tower
		public void AddTower(string towerName)
		{
			var Dict = new Dictionary<string, string>()
			{
				{ "PAM",			"11406" },
				{ "AD",				"14106" },
				{ "BACKUP",			"11400" },
				{ "CITRIX",			"11401" },
				{ "DAM",			"11402" },
				{ "DATABASE",		"11403" },
				{ "DC",				"11404" },
				{ "EUC(INTUNE)",	"14204" },
				{ "EUC(2FA)",		"14300" },
				{ "HVPN",			"14107" },
				{ "NETWORK",		"11405" },
				{ "SECURITY",		"11407" },
				{ "STORAGE",        "11408" },
				{ "SYSTEM",			"11409" },
				{ "UNIX",			"11410" }
			};

			string towerID = Dict[towerName.Trim().ToUpper()];

			fields.customfield_11800.Add(new Dictionary<string, string> { { "id", towerID } });
		}

		//add assignee
		public void AddAssignee(string userName)
		{
			var assignee = new NameItems();
			assignee.name = userName;
			fields.assignee = assignee;
		}

		//add description - append new line.
		public void AppendDescription(string message)
		{
			fields.description += "\n\n" + message;
		}

	}

	public class Fields
	{
		//general
		public string summary { get; set; }
		public string description { get; set; }
		public Dictionary<string, string> project { get; set; }

		//serice desk
		public Dictionary<string, string> issuetype { get; set; }
		public string customfield_10001 { get; set; }

		//configuration items
		public List<ConfigItems> customfield_11105 { get; set; }

		//assigned tower
		public List<Dictionary<string, string>> customfield_11800 { get; set; }

		//assignee
		public NameItems assignee { get; set; }
	}

	public class ConfigItems
	{
		public string key { get; set; }
	}

	public class NameItems
	{
		public string name { get; set; }
	}

	#endregion

	#region Public Class - to construct json body to comment on Jira Ticket
	public class JiraComment
	{
		public string body { get; set; }

		public void AddCommentLine(string message)
		{
			var sb = new StringBuilder();
			sb.AppendLine(message + Environment.NewLine);
			body += sb;
		}

	}
	#endregion

	#region Public Class - to construst json body to query Jira CMDB

	public class CmdbQuery 
	{
		public string objectTypeId { get; set; } = "956";
		public int page { get; set; } = 1;
		public int asc { get; set; } = 1;
		public string orderByTypeAttrId { get; set; } = "13387";
		public int resultsPerPage { get; set; } = 25;
		public bool includeAttributes { get; set; } = true;
		public string iql { get; set; }
		public int objectSchemaId { get; set; } = 47;

		public CmdbQuery(string address) 
		{
			Init(address);
		}

		public void Init(string address)
		{
			IPAddress ip;
			bool isIP = IPAddress.TryParse(address, out ip);

			//IP Address
			if (isIP == true)
			{
				iql = "ObjectType = Host And \"Production LAN IP\" = " + address.Trim().ToUpper();
			}

			//Hostname
			if (isIP == false)
			{
				iql = "ObjectType = Host And Name = " + address.Trim().ToUpper();
			}
		}
	}
	
	#endregion

	#region Public Class - to call API to jira
	
	public class JiraApi
	{
		public string username { get; set; }
		public string password { get; set; }

		public string url { get; set; }
		public string method { get; set; } = "GET";
		public string body { get; set; }
		public int timeout { get; set; } = 60000; //60 seconds

		private RestClient client { get; set; }
		private void SetNewClient()
		{
			client = new RestClient(url);
			client.Timeout = timeout;
		}

		private RestRequest request { get; set; }
		private void SetNewRequest()
		{
			switch (method.Trim().ToUpper())
			{
				case "GET":
					request = new RestRequest(Method.GET);
					break;
				case "POST":
					request = new RestRequest(Method.POST);
					break;
			}
		}

		private void AddAuthHeader()
		{
			var plainText = username + ":" + password;
			var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
			var Base64EncodeText = System.Convert.ToBase64String(plainTextBytes);
			string authHeader = "Basic " + Base64EncodeText;
			request.AddHeader("Authorization", authHeader);
		}
		private void AddHeader()
		{
			request.AddHeader("Content-type", "application/json");
		}

		private void AddBody()
		{
			if (string.IsNullOrEmpty(body) == false)
			{
				request.AddJsonBody(body);
			}
		}

		public IRestResponse Call()
		{
			SetNewClient();
			SetNewRequest();
			AddAuthHeader();
			AddHeader();
			AddBody();
			IRestResponse response = client.Execute(request);
			return response;
		}
	}

	#endregion

	#region Public Class - to handle API response

	public class ApiReponse
	{
		public IRestResponse Response { get; set; }
		public JObject Jobject { get; set; }
		public int StatusCode { get; set; }
	}

	public class JiraQueryResponse : ApiReponse
	{
		public JiraQueryResponse(IRestResponse restResponse)
		{
			Response = restResponse;
			Jobject = Newtonsoft.Json.Linq.JObject.Parse(Response.Content);
		}

		private string CustomFieldId_Ci { get; set; }

		private string[] GetCustomFieldArray(string customFieldId)
		{
			bool j_Fields_Exist = Jobject.TryGetValue("fields", out JToken jToken_field);
			if (j_Fields_Exist == true)
			{
				JObject j_Fields = JObject.Parse(jToken_field.ToString());
				bool j_CustomField_Exist = j_Fields.TryGetValue(customFieldId, out JToken jToken_customField);
				if (j_CustomField_Exist == true)
				{
					if (jToken_customField.Type == JTokenType.Array)
					{
						JArray jArray = (JArray)j_Fields[customFieldId];
						string[] cItems = new string[jArray.Count];
						for (int i = 0; i < jArray.Count; i++)
						{
							cItems[i] = jArray[i].ToString().Split(' ')[1].Trim().Replace("(","").Replace(")","").ToUpper();
						}
						return cItems;
					}
				}
			}
			return new string[0];
		}

		public string GetAssignee()
		{
			bool j_Fields_Exist = Jobject.TryGetValue("fields", out JToken jToken_field);
			if (j_Fields_Exist == true)
			{
				JObject j_Fields = JObject.Parse(jToken_field.ToString());
				bool j_Assignee_Exist = j_Fields.TryGetValue("assignee", out JToken jToken_Assignee);
				if (j_Assignee_Exist == true)
				{
					JObject j_Assignee = JObject.Parse(jToken_Assignee.ToString());
					bool j_Name_Exist = j_Assignee.TryGetValue("name", out JToken jToken_Name);
					if (string.IsNullOrEmpty(jToken_Name.ToString()) == false)
					{
						return (string)j_Assignee["name"];
					}
				}
			}
			return null;
		}

		public string GetStatus()
		{
			bool j_Fields_Exist = Jobject.TryGetValue("fields", out JToken jToken_field);
			if (j_Fields_Exist == true)
			{
				JObject j_Fields = JObject.Parse(jToken_field.ToString());
				bool j_Status_Exist = j_Fields.TryGetValue("status", out JToken jToken_Status);
				if (j_Status_Exist == true)
				{
					JObject j_Status = JObject.Parse(jToken_Status.ToString());
					bool j_Name_Exist = j_Status.TryGetValue("name", out JToken jToken_Name);
					if (string.IsNullOrEmpty(jToken_Name.ToString()) == false)
					{
						return (string)j_Status["name"];
					}
				}
			}
			return null;
		}

		public string GetCustomField(string customFieldId)
		{
			bool j_Fields_Exist = Jobject.TryGetValue("fields", out JToken jToken_field);
			if (j_Fields_Exist == true)
			{
				JObject j_Fields = JObject.Parse(jToken_field.ToString());
				bool j_CustomField_Exist = j_Fields.TryGetValue(customFieldId, out JToken jToken_customField);
				if (j_CustomField_Exist == true)
				{
					if (jToken_customField.Type != JTokenType.Array)
					{
						return (string)j_Fields[customFieldId];
					}
				}
			}
			return null;
		}

		public bool ValidateCI(string CI, string CustomFieldId_Ci)
		{
			string[] cItems = GetCustomFieldArray(CustomFieldId_Ci);
			return Array.Exists(cItems, x => x == CI);
		}
	}

	public class JiraCreateTicketResponse : ApiReponse
	{
		public JiraCreateTicketResponse(IRestResponse restResponse)
		{
			Response = restResponse;
			Jobject = Newtonsoft.Json.Linq.JObject.Parse(Response.Content);
			StatusCode = (int)Response.StatusCode;
		}

		public string GetTicketID()
		{
			bool json_key_Exist = Jobject.TryGetValue("key", out JToken jToken_key);
			if (json_key_Exist == true)
			{
				return (string)Jobject["key"];
			}
			return null;
		}

		public string GetError()
		{
			string key = "errors";

			bool json_errors_Exist = Jobject.TryGetValue(key, out JToken jToken_errors);
			if (json_errors_Exist == true)
			{
				JObject Jobject_errors = JObject.Parse(jToken_errors.ToString());
				return Jobject_errors.First.ToString();
			}
			return null;
		}
	}

	public class CmdbQueryResponse : ApiReponse
	{
		public CmdbQueryResponse(IRestResponse restResponse)
		{
			Response = restResponse;
			Jobject = Newtonsoft.Json.Linq.JObject.Parse(Response.Content);
			ConfigItem_ID = GetConfigItem_ID();
		}

		public string ConfigItem_ID { get; set; }

		private string GetConfigItem_ID()
		{
			bool json_objectEntries_Exist = Jobject.TryGetValue("objectEntries", out JToken jToken_objectEntries);
			if (json_objectEntries_Exist == true)
			{
				JArray jArray_objectEntries = (JArray)Jobject["objectEntries"];

				//if array is empty, return null, no ID found
				if (jArray_objectEntries.Count == 0)
				{
					return null;
				}

				//If jArray_objectEntries have more than 1 count, get the last one.
				int id_count = jArray_objectEntries.Count - 1;

				//Convert to JObject
				JObject jsonResponse_objectEntries = JObject.Parse(jArray_objectEntries[id_count].ToString());

				//Validate objectKey exist
				bool json_objectKey_Exist = jsonResponse_objectEntries.TryGetValue("objectKey", out JToken jToken_objectKey);
				if (json_objectKey_Exist == true)
				{
					return (string)jsonResponse_objectEntries["objectKey"];
				}
			}

			return null;
		}
	}

	#endregion

}




