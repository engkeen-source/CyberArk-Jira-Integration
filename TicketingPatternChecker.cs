using System;
using System.IO;
using System.Xml;
using System.Net;
using System.Globalization;
using System.Text.RegularExpressions;
using CyberArk.PasswordVault.PublicInterfaces;

namespace TicketingChecker{

	#region Public Class - Main
	public class TicketingPatternChecker : ITicketVaildatorEx {

		#region Public Parameters
		//Use TLS 1.2
		public const System.Net.SecurityProtocolType SecurityProtocol = SecurityProtocolType.Tls12;

		//PVWA hostname
		public string pvwaHostname = System.Net.Dns.GetHostName();

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

		//set error messages
		public string msgInvalidTicketFormat			= string.Empty;

		//set bypass checker code
		public string bypassTicketingCheckerCode		= string.Empty;

		//set allowTicketFormatRegex
		public string allowTicketFormatRegex			= string.Empty;

		//internal paramater
		public string logMessage						= string.Empty;
		public string errorMessage						= string.Empty;
		public string auditMessage						= string.Empty;

		//EmergencyMode
		public bool emergencyMode						= false;

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

			if (parameters.AdditionalProperties.ContainsKey("Hostname"))
			{
				cybrHostname	= parameters.AdditionalProperties["Hostname"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Database"))
			{
				cybrDatabase	= parameters.AdditionalProperties["Database"];
			}
			if (parameters.AdditionalProperties.ContainsKey("Port"))
			{
				cybrPort	= parameters.AdditionalProperties["Port"];
			}
			
			//set ticketing parameter
			ticketingSys		= parameters.SystemName.ToUpper();
			ticketingID			= parameters.TicketId.Trim().ToUpper();

			//Audit
			auditMessage = string.Format("PVWA={0} | Input={1} | DualControl={2} | DualControlRequestConfirmed={3} |", pvwaHostname, ticketingID, cybrDualControl, cybrDualControlRequestConfirmed);

			#endregion

			#region Log
			LogWrite("[ Initializing process ] ...");

			LogWrite("[ Fetching PVWA Hostname ] ...");
			LogWrite(string.Format("{0}: {1}", "PVWA Hostname", pvwaHostname));

			LogWrite("[ Fetching XML parameter ]...");
			LogWrite(string.Format("{0}: {1}", "msgInvalidTicketFormat"				, msgInvalidTicketFormat));
			LogWrite(string.Format("{0}: {1}", "bypassTicketingCheckerCode"			, bypassTicketingCheckerCode));

			
			LogWrite("[ Fetching Ticketing connection account -> Additional Properties ]");
			foreach (var item in parameters.TicketingConnectionAccount.Properties)
			{
				if (item.Key == "LastFailDate" || item.Key == "LastSuccessChange" || item.Key == "LastSuccessReconciliation")
				{
					LogWrite(string.Format("{0}: {1}", item.Key, UnixTimeStampToDateTime(item.Value)));
				}
				else
				{
					LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
				}

			}

			LogWrite("[ Fetching ticketing parameter ] ");
			LogWrite(string.Format("{0}: {1}", "TicketId"							, parameters.TicketId));
            LogWrite(string.Format("{0}: {1}", "Ticketing System"					, parameters.SystemName));
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

			LogWrite("[ Fetching ticketing parameter -> Additonal Properties ] ");
			foreach (var item in parameters.TicketingConnectionAccount.Properties)
			{
				if (item.Key == "LastFailDate" || item.Key == "LastSuccessChange" || item.Key == "LastSuccessReconciliation")
				{
					LogWrite(string.Format("{0}: {1}", item.Key, UnixTimeStampToDateTime(item.Value)));
				}
				else
				{
					LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
				}

			}
			#endregion

			#region Validate Ticket

			#region check emergencyMode
			//if matching bypass code, return true
			LogWrite("[ Checking TicketID matched BypassID ]");
			switch (IsValueEmpty(bypassTicketingCheckerCode))
			{ 
				case false:
					emergencyMode = Regex.IsMatch(ticketingID, bypassTicketingCheckerCode);
					auditMessage += " Emergency=" + emergencyMode + " | ";
					if (emergencyMode == true)
					{
						auditMessage += "Ticket pattern pass checker successfully.";
						ticketingOutput.TicketAuditOutput = string.Format("{0},{1}", ticketingID, auditMessage);
						LogWrite(ticketingOutput.TicketAuditOutput);
						CsvWrite(ticketingID, " - ticket pattern pass checker successfully");
						LogWrite("[ Process ended ]");
						return true;
					}
					break;
				case true:
					errorMessage = "Please configure bypassTicketingCheckerCode.";
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
                        bValid = false;
                    }
                    if (ChTicketFormatResult == true)
                    {
                        bValid = true;
                    }
                    break;
                case true:
                    errorMessage = "Please configure allowTicketFormatRegex.";
                    return false;
            }

            switch (bValid)
            {
                case false:
                    auditMessage += " TicketID failed to pass the pattern checker.";
                    ticketingOutput.UserMessage = errorMessage;
                    ticketingOutput.TicketAuditOutput = auditMessage;
                    LogWrite("Error: " + errorMessage);
                    LogWrite("Audit: " + auditMessage);
                    CsvWrite(ticketingID, "failed to pass the pattern checker.");
                    break;
                case true:
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
                    break;
                default:
                    throw new InvalidOperationException("Unexpected value of bValid");
            }

            #endregion

            LogWrite("[ Process ended ]");
			return bValid;
			#endregion
		}

        private static string UnixTimeStampToDateTime(string unixTimeStamp)
        {
            //Convert string to Double
            Double.TryParse(unixTimeStamp, out double unixTimeStampDouble);

            // Unix timestamp is seconds past epoch
            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStampDouble).ToLocalTime();
            return dateTime.ToString();
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

		#endregion

		#region Private Function ParseXmlParameters - Capture Ticketing Parameters from PVConfig.xml
		private void ParseXmlParameters(XmlNode xmlParameters){
			//Fetch ticketing parameters from PVWA
			checkParameters = xmlParameters.InnerXml;

			//Allow Ticket Format Regex
			allowTicketFormatRegex				= ExtractValueFromXML(checkParameters, "allowTicketFormatRegex");

			//Error Message
			msgInvalidTicketFormat				= ExtractValueFromXML(checkParameters, "msgInvalidTicketFormat");

            //bypass code
            bypassTicketingCheckerCode			= ExtractValueFromXML(checkParameters, "bypassTicketingCheckerCode").Trim().ToUpper();

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
			var messageToAppend = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}"
					, DateTime.Now.ToString() ,ticketingSys , TicketID , ValidationStatus 
					, cybrReason.Replace(",","|") , cybrSafeName , cybrObjectName , cybrPolicy
					, GetConnectionAddress() , cybrUsername , cybrRequestingUser , cybrRequesterName , cybrEmail
					, cybrDualControl.ToString() , cybrDualControlRequestConfirmed.ToString(), emergencyMode.ToString() );
			messageToAppend += Environment.NewLine;
			File.AppendAllText(csvFile, messageToAppend);
		}

		#endregion
	}

}

#endregion


