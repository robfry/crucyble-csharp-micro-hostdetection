using System;
using System.Collections.Generic;
using System.Net;
using FIDO.HostDetection.FIDO.Support.API.Endpoints;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection
{
  public class SysMgmt_DDI
  {
    public static Object_DDI GetDHCPInfo(FidoReturnValues lFidoReturnValues)
    {
      try
      {
        //if DHCP detection is turned on, then gather DHCP information from DDI
        if (string.IsNullOrEmpty(lFidoReturnValues.Hostname))
        {
          lFidoReturnValues.DDI = new Object_DDI();
          lFidoReturnValues.DDI = GetDDIRecord(lFidoReturnValues);

          if (lFidoReturnValues.DDI.DhcpEntries != null)
          {
            if (lFidoReturnValues.DDI.DhcpEntries[0].DhcpLeaseClientName != null)
            {
              var aryTemp = lFidoReturnValues.DDI.DhcpEntries[0].DhcpLeaseClientName.Split('.');
              lFidoReturnValues.Hostname = aryTemp[0];
            }
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught getting DDI DHCP information:" + e);
      }

      return lFidoReturnValues.DDI;
    }

    private static Object_DDI GetDDIRecord(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Querying DDI for information.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = GetDDIConfigs();

      var request = parseConfigs.rows[0].value.configs.server + parseConfigs.rows[0].value.configs.query[0] + parseConfigs.rows[0].value.configs.query[1].Replace("%sip%", lFidoReturnValues.SrcIP);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      var ddiReturn = new Object_DDI();
      alertRequest.Headers[@"X-IPM-Username"] = parseConfigs.rows[0].value.configs.username;
      alertRequest.Headers[@"X-IPM-Password"] = parseConfigs.rows[0].value.configs.pwd;
      alertRequest.Method = "GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return ddiReturn;
        stringreturn = "{\"entries\":" + stringreturn + "}";
        ddiReturn = JsonConvert.DeserializeObject<Object_DDI>(stringreturn);
        if (ddiReturn.DhcpEntries != null)
        {
          ddiReturn = ParseDDIReturn(ddiReturn, lFidoReturnValues);
        }
        Console.WriteLine(@"Finished getting DDI DHCP information.");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in DDI section:" + e);
      }

      return ddiReturn;
    }

    private static Object_DDI ParseDDIReturn(Object_DDI ddiReturn, FidoReturnValues lFidoReturnValues)
    {

      for (int i = 0; i < ddiReturn.DhcpEntries.Count; i++)
      {
        ddiReturn.DhcpEntries[i].DhcpLeaseTime = FromEpochTime(ddiReturn.DhcpEntries[i].DhcpLeaseTime).ToString();
        ddiReturn.DhcpEntries[i].DhcpLeaseEndTime = FromEpochTime(ddiReturn.DhcpEntries[i].DhcpLeaseEndTime).ToString();
      }

      return ddiReturn;
    }

    private static DateTime? FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(unixTime));
    }

    private static DDIConfigs GetDDIConfigs()
    {
      var configs = new DDIConfigs();
      var request = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_configs_sysmgmt.sysmgmt.vendors + "?key=\"ddi\"";
        //"http://127.0.0.1:5984/fido_configs_sysmgmt/_design/sysmgmt/_view/vendors?key=\"ddi\"";
      var invRequest = (HttpWebRequest)WebRequest.Create(request);
      invRequest.Method = "GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(invRequest);
        if (string.IsNullOrEmpty(stringreturn)) return configs;
        configs = JsonConvert.DeserializeObject<DDIConfigs>(stringreturn);
        if (configs != null)
        {
          return configs;
        }
        Console.WriteLine(@"Finished retrieving DDI configs.");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in SentinelOne alert area:" + e);
      }
      return configs;
    }


    private class DDIConfigs
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }

      internal class Configs
      {
        public string server { get; set; }
        public string username { get; set; }
        public string pwd { get; set; }
        public List<string> query { get; set; }

      }

      internal class Value
      {
        public string _id { get; set; }
        public string _rev { get; set; }
        public int type { get; set; }
        public int server { get; set; }
        public string label { get; set; }
        public string vendor { get; set; }
        public Configs configs { get; set; }
      }

      internal class Row
      {
        public string id { get; set; }
        public string key { get; set; }
        public Value value { get; set; }
      }
    }
  }

}
