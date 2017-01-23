using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using FIDO.HostDetection.FIDO.Support.API.Endpoints;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.Event.Queue;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.RabbitMQ;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection.WhiteList
{
  static class GetWhiteList
  {
    private static void Main(string[] args)
    {
      RunWhiteList();
    }

    private static void RunWhiteList()
    {
      try
      {
        var postrabbit = new PostRabbit();
        while (true)
        {
          var lFidoReturnValues = GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.hostdetection.whitelist.queue, GetRabbitEnum.Whitelist);
          if (lFidoReturnValues == null) continue;

          //todo: put the IP in the DB
          if (lFidoReturnValues.SrcIP.StartsWith("100.127."))
          {
            postrabbit.SendToRabbit(lFidoReturnValues.TimeOccured, lFidoReturnValues.UUID, EventQueue.PrimaryConfig.hostdetection.vpn.exchange, EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig);
          }

          if (!EvalWhitelist(lFidoReturnValues))
          {
            //todo: if there is no VPN configured then check and route msg to datasources exchange instead
            if (EventQueue.PrimaryConfig?.datasources?.inventory?.landesk?.exchange != null) postrabbit.SendToRabbit(lFidoReturnValues.TimeOccured, lFidoReturnValues.UUID, EventQueue.PrimaryConfig.datasources.inventory.landesk.exchange, EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig);
          }
          GC.Collect();
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering rabbitmq events:" + e);
      }
    }

    private static bool EvalWhitelist(FidoReturnValues lFidoReturnValues)
    {
      var isFound = false;
      try
      {
        //check detector values versus whitelist and exclude if true
        isFound = CheckFidoWhitelist(lFidoReturnValues.SrcIP, lFidoReturnValues.DstIP, lFidoReturnValues.Hash, lFidoReturnValues.DNSName, lFidoReturnValues.Url, lFidoReturnValues.MalwareType, lFidoReturnValues.Hostname);
        if (isFound)
        {
          Console.WriteLine(@"Artifact from alert is whitelisted.");
          return isFound;
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Director processing whitelist:" + e);
      }
      return isFound;
    }

    private static bool CheckFidoWhitelist(string sSrcIP, List<string> sDstIP, List<string> sHash, string sDomain, List<string> sUrl, string sMalwareType, string sHostname)
    {
      if (sHash.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(sHash));
      if (sUrl.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(sUrl));
      if (sDstIP.Count == 0) throw new ArgumentException("Value cannot be an empty collection.", nameof(sDstIP));
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_events_whitelist.whitelist.entries;
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Method = @"GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(request);
        if (string.IsNullOrEmpty(stringreturn)) return false;
        var tempReturn = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_Whitelist.Whitelist>(stringreturn);

        foreach (var entry in tempReturn.rows[0].key)
        {
          if (entry == null) continue;
          switch (entry.type)
          {
            case 0:
              if (sHash != null && sHash.Any(hash => entry.artifact == hash))
              {
                return true;
              }
              break;

            case 1:
              if (sSrcIP != null && (entry.artifact == sSrcIP | sDstIP.Any(dst => entry.artifact == dst)))
              {
                return true;
              }
              break;

            case 2:
              if (sDomain != null && sDomain == entry.artifact)
                return true;
              break;

            case 3:
              if (sUrl != null && sUrl.Any(url => entry.artifact == url))
                return true;
              break;

            case 4:
              if (sHostname != null && sHostname == entry.artifact)
                return true;
              break;

            case 5:
              if (sMalwareType != null && sMalwareType == entry.artifact)
              {
                return true;
              }
              break;
          }
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error",
          "Fido Failed: {0} Exception caught in getting whitelist json from CouchDB:" + e);
      }

      return false;
    }
  }
}
