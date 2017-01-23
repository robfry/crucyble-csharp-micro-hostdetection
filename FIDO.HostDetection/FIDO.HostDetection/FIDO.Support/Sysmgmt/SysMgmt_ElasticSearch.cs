using System;
using System.Net;
using System.Text.RegularExpressions;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection.FIDO.Support.Sysmgmt
{
  public class SysMgmt_ElasticSearch
  {
    public static FidoReturnValues RunVPN(FidoReturnValues lFidoReturnValues)
    {
      var VPNSrcIP = SysMgmt_ElasticSearch.QueryESDB(lFidoReturnValues.SrcIP, null, Enum_F5_VPN.IP);
      if (VPNSrcIP.entries != null)
      {
        var entry = new Object_F5_VPN.Hit();
        foreach (var hit in VPNSrcIP.entries.hits)
        {
          if (string.IsNullOrEmpty(entry._score))
          {
            entry = hit;
          }
          if (entry._source.es_timestamp < hit._source.es_timestamp)
          {
            entry = hit;
          }

        }

        if (entry._source != null)
        {
          var common = SysMgmt_ElasticSearch.ParseQueryReturn(entry._source.message, Object_F5_VPN_Search.Common);
          var retVPN = SysMgmt_ElasticSearch.QueryESDB(null, common, Enum_F5_VPN.Record);
          lFidoReturnValues.VPN = new Object_F5_VPN.ESVPN();
          lFidoReturnValues.VPN = retVPN;
          var parseVPN = new VPN_F5();
          var returnVPN = parseVPN.ParseQueryReturn(lFidoReturnValues.VPN);
          lFidoReturnValues.Inventory = new Inventory { VPN = new Object_F5_VPN_Inventory() };
          lFidoReturnValues.Inventory.VPN = returnVPN;

          if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.VPN.HostName)) lFidoReturnValues.Hostname = lFidoReturnValues.Inventory.VPN.HostName;
          if (!string.IsNullOrEmpty(lFidoReturnValues.Inventory.VPN.UserName)) lFidoReturnValues.Username = lFidoReturnValues.Inventory.VPN.UserName.Replace("'", string.Empty);
          return lFidoReturnValues;
        }
      }
      return null;
    }

    public static Object_F5_VPN.ESVPN QueryESDB(string SrcIP, Enum_F5_VPN Type)
    {
      return null;
    }

    public static Object_F5_VPN.ESVPN QueryESDB(string SrcIP, string Common, Enum_F5_VPN Type)
    {
      var query = ESQuery(SrcIP, Common, Type);

      Console.WriteLine(@"Querying ES for VPN host/user.");

      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var esReturn = new Object_F5_VPN.ESVPN();

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return esReturn;
        esReturn = JsonConvert.DeserializeObject<Object_F5_VPN.ESVPN>(stringreturn);
        return esReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying ES:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying ES:" + e);
      }

      return esReturn;
    }

    private static string ESQuery(string SrcIp, string Common, Enum_F5_VPN Type)
    {
      var tempmonth = DateTime.Now.Month;
      var month = string.Empty;
      if (tempmonth.ToString().Length == 1)
      {
        month = @"0" + tempmonth;
      }
      else
      {
        month = tempmonth.ToString();
      }

      var sDate = DateTime.Now.Year + @"" + month;
      var index = @"vpnf5" + sDate;

      switch (Type)
      {
        //todo:move this to DB
        case Enum_F5_VPN.IP:
          return @"http://esidentity.itp.netflix.net:7104/" + index + "/_search?q=" + '"' + "IPv4: " + SrcIp + '"' + "&size=100";
        case Enum_F5_VPN.Record:
          return @"http://esidentity.itp.netflix.net:7104/" + index + "/_search?q=" + '"' + Common + '"' + " AND (\"01490005\" OR \"01490128\" OR \"01490102\" OR \"01490248\" OR \"01490010\" OR \"01490500\" OR \"01490506\")";

        default:
          throw new Exception();
      }
    }

    public static string ParseQueryReturn(string Msg, string Pattern)
    {
      var regex = new Regex(Pattern, RegexOptions.Singleline);
      var regreturn = regex.Match(Msg);
      return regreturn.Value;
    }

    public static string ParseQueryReturn(string Msg, Object_F5_VPN_Search Pattern)
    {
      var regex = new Regex(Pattern.Value, RegexOptions.Singleline);
      var regreturn = regex.Match(Msg);
      return regreturn.Value;
    }
  }
}
