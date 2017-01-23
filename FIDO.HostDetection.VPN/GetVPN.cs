using System;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.Event.Queue;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.RabbitMQ;


namespace FIDO.HostDetection.VPN.F5
{
  static class GetVPN
  {
    private static void Main(string[] args)
    {
      GetVPNQueue();
    }

    private static void GetVPNQueue()
    {
      try
      {
        while (true)
        {
          var lFidoReturnValues = GetRabbit.ReceiveNotificationQueue(EventQueue.PrimaryConfig.host, EventQueue.PrimaryConfig.hostdetection.vpn.f5.queue, GetRabbitEnum.F5);
          if (lFidoReturnValues.VPN == null) continue;
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
  }
}
