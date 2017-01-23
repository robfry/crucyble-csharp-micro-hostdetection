using System;
using System.Net;
using System.Text;
using FIDO.HostDetection.FIDO.Support.API.Endpoints;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.GeoIP;
using FIDO.HostDetection.FIDO.Support.Rest;
using FIDO.HostDetection.FIDO.Support.Sysmgmt;
using Newtonsoft.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using RabbitMQ.Client.MessagePatterns;

namespace FIDO.HostDetection.FIDO.Support.RabbitMQ
{
  public static class GetRabbit
  {
    public static FidoReturnValues ReceiveNotificationQueue(string host, string queue, GetRabbitEnum typeEnum)
    {
      Console.WriteLine(@"Subscribing to : " + host + @" and queue: " + queue);
      var lFidoReturnValues = new FidoReturnValues();
      var factory = new ConnectionFactory() { HostName = host };
      try
      {
        using (IConnection connection = factory.CreateConnection())
        {
          using (IModel model = connection.CreateModel())
          {
            var subscription = new Subscription(model, queue, false);
            while (true)
            {
              BasicDeliverEventArgs eventMsg = subscription.Next();
              var messageContent = Encoding.UTF8.GetString(eventMsg.Body);

              Console.WriteLine(messageContent);
              var rabbitmq = JsonConvert.DeserializeObject<Object_RabbitMQ.EventMsg>(messageContent);
              if (rabbitmq.notification.uuid == null) return null;
              lFidoReturnValues = GetFidoJson(rabbitmq.notification.uuid);

              lFidoReturnValues = ReturnHostDetection(lFidoReturnValues, typeEnum);

              if (lFidoReturnValues != null)
              {
                subscription.Ack(eventMsg);
              }
              return lFidoReturnValues ?? null;
            }
          }
        }
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        Fido_EventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught retrieving messages from queue:" + e);
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues ReturnHostDetection(FidoReturnValues lFidoReturnValues, GetRabbitEnum typeEnum)
    {
      try
      {
        switch (typeEnum)
        {
          case GetRabbitEnum.DDI:
            var ddiObject = SysMgmt_DDI.GetDHCPInfo(lFidoReturnValues);
            lFidoReturnValues.DDI = new Object_DDI();
            lFidoReturnValues.DDI = ddiObject;
            return lFidoReturnValues;
          case GetRabbitEnum.F5:
            lFidoReturnValues = SysMgmt_ElasticSearch.RunVPN(lFidoReturnValues);
            return lFidoReturnValues;
          case GetRabbitEnum.Maxmind:
            lFidoReturnValues =  GeoIpLookup.FindIP(lFidoReturnValues);
            return lFidoReturnValues;
          case GetRabbitEnum.Whitelist:
            return lFidoReturnValues;
        }

      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        Fido_EventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught retrieving messages from queue:" + e);
      }
      return null;
    }

    private static FidoReturnValues GetFidoJson(string uuid)
    {

      //Load Fido configs from CouchDB
      var query = API_Endpoints.PrimaryConfig.host + API_Endpoints.PrimaryConfig.fido_events_alerts.dbname + @"/" + uuid;
      FidoReturnValues lFidoReturnValues;
      var connect = new Fido_Rest_Connection();

      try
      {
        var connection = (HttpWebRequest)WebRequest.Create(query);
        var stringreturn = connect.RestCall(connection);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        lFidoReturnValues = JsonConvert.DeserializeObject<FidoReturnValues>(stringreturn);
        lFidoReturnValues.UUID = uuid;
        if (lFidoReturnValues == null)
        {
          Console.WriteLine(stringreturn);
        }
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException().Message);
        Fido_EventHandler.SendEmail(e.GetBaseException().Message, "Fido Failed: {0} Exception caught in REST call to CouchDB to retrieve FIDO object:" + e);
        return null;
      }

      return lFidoReturnValues;
    }
  }
}
