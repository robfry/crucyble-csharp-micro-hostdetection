using System;
using System.Net;
using FIDO.HostDetection.FIDO.Support.API.Endpoints;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.Event.Queue;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.RabbitMQ;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection.DHCP.DDI
{
  class GetDHCP
  {
    static void Main(string[] args)
    {
      RunDDI();
    }

    private static void RunDDI()
    {
      try
      {
        while (true)
        {
          var lFidoReturnValues = GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.hostdetection.dhcp.ddi.queue, GetRabbitEnum.DDI);
          if (lFidoReturnValues.DDI == null) continue;
          var writeCouch = new Fido_CouchDB();
          writeCouch.WriteToDBFactory(lFidoReturnValues);
          GC.Collect();
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught gathering rabbitmq events:" + e);
      }
    }

    private static Object_Fido_Configs_CouchDB_App.StartupConfigs GetConfigs()
    {
      //Load Fido configs from CouchDB
      var query = API_Endpoints.PrimaryConfig.host +
                  API_Endpoints.PrimaryConfig.fido_configs.app_configs.startup_configs;
      var request = (HttpWebRequest)WebRequest.Create(query);
      request.Method = @"GET";
      var startupConfigs = new Object_Fido_Configs_CouchDB_App.StartupConfigs();

      try
      {
        var getRest = new Fido_Rest_Connection();
        var stringreturn = getRest.RestCall(request);
        startupConfigs = JsonConvert.DeserializeObject<Object_Fido_Configs_CouchDB_App.StartupConfigs>(stringreturn);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in fidomain area gathering startup configs:" + e);
      }

      return startupConfigs;
    }

  }
}
