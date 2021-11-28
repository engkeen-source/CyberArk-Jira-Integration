using System;
using System.IO;
using System.Xml;
using System.Net;
using System.Globalization;
using System.Text.RegularExpressions;
using CyberArk.PasswordVault.PublicInterfaces;
using Newtonsoft.Json;

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
			ITicketingConnectionAccount connectionAccount	= parameters.TicketingConnectionAccount;

			//Fetch from PVWA
			cybrSafeName					= parameters.SafeName;
			cybrObjectName					= parameters.ObjectName;
			cybrMachineAddress				= parameters.MachineAddress.Trim().ToUpper();
			cybrTransparentMachineAddress	= parameters.TransparentMachineAddress.Trim().ToUpper();
			cybrDualControl					= parameters.DualControl;
			cybrDualControlRequestConfirmed	= parameters.DualControlRequestConfirmed;
			cybrReason						= parameters.ProvidedReason;
			cybrUsername					= parameters.UserName;
			cybrRequesterName				= parameters.RequestingUserFirstName + " " + parameters.RequestingUserSurname;
			cybrEmail						= parameters.RequestingUserEmail;
			cybrPolicy						= parameters.PolicyId;
			cybrRequestingUser				= parameters.RequestingUser.Trim().ToUpper();

			if (parameters.AdditionalProperties.ContainsKey("Tower"))
			{
				cybrTower		= parameters.AdditionalProperties["Tower"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Hostname"))
			{
				cybrHostname	= parameters.AdditionalProperties["Hostname"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Database"))
			{
				cybrHostname	= parameters.AdditionalProperties["Database"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Port"))
			{
				cybrHostname	= parameters.AdditionalProperties["Port"];
			}
			
			//set ticketing parameter
			ticketingSys		= parameters.SystemName.ToUpper();
			ticketingID			= parameters.TicketId.Trim().ToUpper();

			//Set API Logon Parameters
			jiralogonAddress	= parameters.TicketingConnectionAccount.Address;
			jiralogonUsername	= parameters.TicketingConnectionAccount.UserName;
			jiralogonPassword	= parameters.TicketingConnectionAccount.Password;

			//Audit
			auditMessage = string.Format("Input={0} | DualControl={1} | DualControlRequestConfirmed={2} |", ticketingID, cybrDualControl, cybrDualControlRequestConfirmed);

			#endregion

			#region Log
			LogWrite("Initializing process ...");
			LogWrite("Fetched XML parameter");
			LogWrite(string.Format("{0}: {1}", "allowedChangeTicketStatus"			, allowedChangeTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedServiceRequestTicketStatus"	, allowedServiceRequestTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedIncidentTicketStatus"		, allowedIncidentTicketStatus));
			LogWrite(string.Format("{0}: {1}", "allowedProblemTicketStatus"			, allowedProblemTicketStatus));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicket"					, msgInvalidTicket));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicketFormat"				, msgInvalidTicketFormat));
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicketStatus"				, msgInvalidTicketStatus));
			LogWrite(string.Format("{0}: {1}", "msgConnectionError"					, msgConnectionError));
			LogWrite(string.Format("{0}: {1}", "msgInvalidAccessTime"				, msgInvalidAccessTime));
			LogWrite(string.Format("{0}: {1}", "msgInvalidMachine"					, msgInvalidMachine));
			LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer"				, msgInvalidImplementer));
			LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer"				, chkLogonToTicketingSystem));
			LogWrite(string.Format("{0}: {1}", "enChkTime"							, enChkTime));
			LogWrite(string.Format("{0}: {1}", "enChkCI"							, enChkCI));
			LogWrite(string.Format("{0}: {1}", "enChkImplementer"					, enChkImplementer));
			LogWrite(string.Format("{0}: {1}", "bypassJiraValidationCode"			, bypassJiraValidationCode));
			LogWrite(string.Format("{0}: {1}", "createJiraIncValidationCode"		, createJiraIncValidationCode));
			LogWrite("Fetched connecting account to " + ticketingSys);
			LogWrite(string.Format("{0}: {1}", "jiralogonAddress"					, jiralogonAddress));
			LogWrite(string.Format("{0}: {1}", "jiralogonUsername"					, jiralogonUsername));
			LogWrite(string.Format("{0}: {1}", "Jira Object Name"					, parameters.TicketingConnectionAccount.ObjectName));
			LogWrite(string.Format("{0}: {1}", "Jira Safe Name"						, parameters.TicketingConnectionAccount.Safe));
			LogWrite(string.Format("{0}: {1}", "Jira Folder Name"					, parameters.TicketingConnectionAccount.Folder));
			LogWrite("Fetched connecting account to " + ticketingSys + " -> Additional Properties");
			foreach (var item in parameters.TicketingConnectionAccount.Properties)
			{
				LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
			}

			LogWrite("Fetched ticketing parameter.");
			LogWrite(string.Format("{0}: {1}", "TicketId"							, parameters.TicketId));
			LogWrite(string.Format("{0}: {1}", "SafeName"							, parameters.SafeName));
			LogWrite(string.Format("{0}: {1}", "FolderName"							, parameters.FolderName));
			LogWrite(string.Format("{0}: {1}", "ObjectName"							, parameters.ObjectName));
			LogWrite(string.Format("{0}: {1}", "MachineAddress"						, parameters.MachineAddress));
			LogWrite(string.Format("{0}: {1}", "TransparentMachineAddress"			, parameters.TransparentMachineAddress));
			LogWrite(string.Format("{0}: {1}", "UserName"							, parameters.UserName));
			LogWrite(string.Format("{0}: {1}", "PolicyId"							, parameters.PolicyId));
			LogWrite(string.Format("{0}: {1}", "RequestingUser"						, parameters.RequestingUser));
			LogWrite(string.Format("{0}: {1}", "RequestingUserFirstName"			, parameters.RequestingUserFirstName));
			LogWrite(string.Format("{0}: {1}", "RequestingUserSurName"				, parameters.RequestingUserSurname));
			LogWrite(string.Format("{0}: {1}", "BusinessEmail"						, parameters.RequestingUserEmail));
			LogWrite(string.Format("{0}: {1}", "ProvidedReason"						, parameters.ProvidedReason));
			LogWrite(string.Format("{0}: {1}", "SystemName"							, parameters.SystemName));
			LogWrite(string.Format("{0}: {1}", "DualControl"						, parameters.DualControl));
			LogWrite(string.Format("{0}: {1}", "DualControlRequestConfirmed"		, parameters.DualControlRequestConfirmed));

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
			switch (IsValueEmpty(createJiraIncValidationCode))
			{
				case false:
					bool ChCreateInc = Regex.IsMatch(ticketingID, createJiraIncValidationCode.Trim().ToUpper());
					if (ChCreateInc == true)
					{
						LogWrite("Entering Function CreateTicketIdUsingTicketingSystem()");
						ticketingID = null;
						ticketingID = CreateTicketIdUsingTicketingSystem();

						switch (IsValueEmpty(ticketingID))
						{
							case true:
								ticketingOutput.UserMessage = errorMessage + " TicketID failed to create.";
								ticketingOutput.TicketAuditOutput = auditMessage + " TicketID failed to create.";
								LogWrite(ticketingOutput.UserMessage);
								LogWrite(ticketingOutput.TicketAuditOutput);
								CsvWrite("", "Failed to Create");
								LogWrite("Process ended...");
								return false;
							case false:
								ticketingOutput.TicketId = ticketingID;
								ticketingOutput.TicketAuditOutput = " " + auditMessage + ticketingID + " created successfully.";
								LogWrite("TicketId: " + ticketingID);
								LogWrite(ticketingOutput.TicketAuditOutput);
								CsvWrite(ticketingID, "Created Successfully");
								LogWrite("Process ended...");
								return true;
						}
					}
					break;
			}
			#endregion

			#region Validate Ticket

			#region check emergencyMode
			//if matching bypass code, return true
			LogWrite("Checking TicketID matched BypassID...");
			switch (IsValueEmpty(bypassJiraValidationCode))
			{ 
				case false:
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
					break;
				case true:
					errorMessage = "Please configure bypassJiraValidationCode.";
					return false;
			}
			#endregion

			#region check ticket format
			//if ticket format is incorrect, return false
			LogWrite("Checking TicketID is in correct format...");
			switch (IsValueEmpty(allowTicketFormatRegex))
			{
				case false:
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
					break;
				case true :
					errorMessage = "Please configure allowTicketFormatRegex.";
					return false;
			}
			#endregion

			#region check connection to Jira
			switch (connectionAccount == null)
			{ 
				case true :
					ticketingOutput.UserMessage = "No ticketing system login account was specified";
					LogWrite(ticketingOutput.UserMessage);
					LogWrite("Process ended...");
					return bValid;
				case false :
					switch (chkLogonToTicketingSystem)
					{
						case true:
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
							break;
						case false :
							LogWrite("Successfully logon to Jira: " + "Not checked");
							break;
					}
					break;
			}
			#endregion

			#region check ticket validity
			LogWrite("Checking TicketID validity...");
			bValid = CheckTicketIdValidity(ticketingID);
			#endregion

			#region post-validation
			switch (bValid)
			{ 
				case false :
					auditMessage += " TicketID validation failed.";
					ticketingOutput.UserMessage = errorMessage;
					ticketingOutput.TicketAuditOutput = auditMessage;
					LogWrite("Error: " + errorMessage);
					LogWrite("Audit: " + auditMessage);
					CsvWrite(ticketingID, "Failed to Validate");
					break;
				case true :
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
					break;
			}
			#endregion

			LogWrite("Process ended...");
			return bValid;
			#endregion
		}

		//If value not empty, write to comment object
		private void OutputToCommentIfNotEmpty(JiraComment comment, string key, string value)
		{
			switch (IsValueEmpty(value))
			{	
				case false:
					comment.AddCommentLine(string.Format("{0}: {1}", key, value));
					break;
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
			switch (IsValueEmpty(cybrTower))
			{
				case true:
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

			//Capture response
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

			//Capture response
			var response = LogonToJira.Call();
			var responseHandle = new JiraCreateTicketResponse(response);

			//Get ticketID
			switch (responseHandle.StatusCode)
			{
				case 201:
					return responseHandle.GetTicketID();
				default:
					errorMessage = "API response status code is not 201(created). " + responseHandle.GetError();
					return null;
			}			
		}

		//If value not empty, write to comment object
		private void OutputToIncDescIfNotEmpty(Ticket incidentTicket, string key, string value)
		{
			switch (IsValueEmpty(value))
			{
				case false:
					incidentTicket.AppendDescription(string.Format("{0}: {1}", key, value));
					break;
			}
		}
		#endregion

		#region Private Function CheckTicketIdValidity - return TRUE if ticket is valid
		private bool CheckTicketIdValidity(string ticketID)
		{
			LogWrite("Entered CheckTicketIdValidity()");

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

			switch (response.IsSuccessful)
			{ 
				case true:
					var JiraQuery = new JiraQueryResponse(response);

					bool ChkCIResult;
					bool ChkTimeResult;
					bool ChkImplementerResult;
					bool ChkCurrentTicketStatus;

					switch (ticketCategory)
					{
						//Change Ticket
						case "CR":
							ChkTimeResult = ValidateTime(JiraQuery);
							ChkCIResult = ValidateCI(JiraQuery);
							ChkImplementerResult = ValidateAssignee(JiraQuery);
							ChkCurrentTicketStatus = ValidateTicketStatus(JiraQuery, ticketCategory);
							break;

						//Service Ticket
						case "SR":
							ChkTimeResult = true;
							ChkCIResult = true;
							ChkImplementerResult = ValidateAssignee(JiraQuery);
							ChkCurrentTicketStatus = ValidateTicketStatus(JiraQuery, ticketCategory);
							break;

						//Incident Ticket
						case "INC":
							ChkTimeResult = true;
							ChkCIResult = true;
							ChkImplementerResult = ValidateAssignee(JiraQuery);
							ChkCurrentTicketStatus = ValidateTicketStatus(JiraQuery, ticketCategory);
							break;

						//Problem Ticket
						case "PR":
							ChkTimeResult = true;
							ChkCIResult = true;
							ChkImplementerResult = ValidateAssignee(JiraQuery);
							ChkCurrentTicketStatus = ValidateTicketStatus(JiraQuery, ticketCategory);
							break;

						default:
							errorMessage += "Ticket was not configured to be validated.";
							return false;
					}
					return (ChkTimeResult && ChkCIResult && ChkImplementerResult && ChkCurrentTicketStatus);

				case false:
					errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicket);
					break;
			}

			errorMessage = "Did not receive response from Jira.";
			LogWrite(errorMessage);
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



}




