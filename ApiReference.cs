using System;
using System.Net;
using System.Text;
using System.Collections.Generic;
using RestSharp;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


//Git

namespace Jira.TicketingValidation
{
    #region Public Class - to contrust json body to create Jira Ticket
    //Reference - https://developer.atlassian.com/server/jira/platform/jira-rest-api-examples/

    public class Ticket
    {
        public Fields fields { get; set; }
        public Ticket(string ticketType)
        {
            fields = new Fields()
            {
                description = "Ticket created from PAM Web portal.",

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
                { "PAM",            "11406" },
                { "AD",             "14106" },
                { "BACKUP",         "11400" },
                { "CITRIX",         "11401" },
                { "DAM",            "11402" },
                { "DATABASE",       "11403" },
                { "DC",             "11404" },
                { "EUC(INTUNE)",    "14204" },
                { "EUC(2FA)",       "14300" },
                { "HVPN",           "14107" },
                { "NETWORK",        "11405" },
                { "SECURITY",       "11407" },
                { "STORAGE",        "11408" },
                { "SYSTEM",         "11409" },
                { "UNIX",           "11410" }
            };

            //Check tower exist
            switch (Dict.ContainsKey(towerName))
            {
                case true: 
                    string towerID = Dict[towerName.Trim().ToUpper()];
                    fields.customfield_11800.Add(new Dictionary<string, string> { { "id", towerID } });
                    break;
            }


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
        [JsonProperty(PropertyName = "public")]
        public string publicType { get; set; }

        public JiraComment()
        {
            publicType = "false";
        }

        public void AddCommentLine(string message)
        {
            var sb = new StringBuilder();
            sb.AppendLine(message + Environment.NewLine);
            body += sb;
        }

    }
    #endregion

    #region Public Class - to construst json body to query Jira CMDB

    public class CmdbQueryHost
    {
        public string objectTypeId { get; set; } = "956";
        public int page { get; set; } = 1;
        public int asc { get; set; } = 1;
        public string orderByTypeAttrId { get; set; } = "13387";
        public int resultsPerPage { get; set; } = 25;
        public bool includeAttributes { get; set; } = true;
        public string iql { get; set; }
        public int objectSchemaId { get; set; } = 47;

        public CmdbQueryHost(string address)
        {
            SetIql(address);
        }

        public void SetIql(string address)
        {
            bool isIP = IPAddress.TryParse(address, out _);

            switch (isIP)
            { 
                //Address is IP
                case true:
                    iql = "ObjectType = Host And \"Production LAN IP Address\" = " + address.Trim().ToUpper();
                    break;

                //Address is hostname/FQDN
                case false:
                    iql = "ObjectType = Host And Name = " + address.Trim().ToUpper();
                    break;
            }
        }
    }
    public class CmdbQueryNetworkDevice
    {
        public string objectTypeId { get; set; } = "974";
        public int page { get; set; } = 1;
        public int asc { get; set; } = 1;
        public string orderByTypeAttrId { get; set; } = "13387";
        public int resultsPerPage { get; set; } = 25;
        public bool includeAttributes { get; set; } = true;
        public string iql { get; set; }
        public int objectSchemaId { get; set; } = 47;

        public CmdbQueryNetworkDevice(string address)
        {
            SetIql(address);
        }

        public void SetIql(string address)
        {
            iql = "ObjectType = \"Network and Security Device\" And Name = " + address.Trim().ToUpper();
        }
    }

    #endregion

    #region Public Class - to call API to jira

    public class JiraApi
    {
        public const System.Net.SecurityProtocolType SecurityProtocol = SecurityProtocolType.Tls12;

        public string username { get; set; }
        public string password { get; set; }

        public string url { get; set; }
        public string method { get; set; }
        public string body { get; set; }
        public int timeout { get; set; }

        private RestClient client { get; set; }

        //Method
        private void SetNewClient()
        {
            client = new RestClient(url);
            //bypass ssl validation check by using RestClient object
            client.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
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
        private string CustomFieldId_Ci { get; set; }

        public JiraQueryResponse(IRestResponse restResponse)
        {
            Response = restResponse;
            Jobject = Newtonsoft.Json.Linq.JObject.Parse(Response.Content);
        }

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
                            cItems[i] = jArray[i].ToString().Split(' ')[1].Trim().Replace("(", "").Replace(")", "").ToUpper();
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
            bool json_key_Exist = Jobject.TryGetValue("key", out _);
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
