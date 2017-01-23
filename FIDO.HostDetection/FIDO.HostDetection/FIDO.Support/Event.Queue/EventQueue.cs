using System;
using System.Net;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection.FIDO.Support.Event.Queue
{
  public class EventQueue
  {
    public static readonly Object_Event_Queue.PrimaryConfig PrimaryConfig = QueConfigClean();

    private static Object_Event_Queue.Queues GetQueues()
    {
      var query = "http://127.0.0.1:5984/fido_configs_queues/_design/queues/_view/map";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new Object_Event_Queue.Queues();

      try
      {
        var getRest = new Fido_Rest_Connection();
        stringreturn = getRest.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
        cdbReturn = JsonConvert.DeserializeObject<Object_Event_Queue.Queues>(stringreturn);
        return cdbReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }

      return cdbReturn;
    }

    private static Object_Event_Queue.PrimaryConfig QueConfigClean()
    {
      var Que = GetQueues();
      if (Que == null) throw new ArgumentNullException("Que");
      var que = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test : Que.rows[0].key.queues.production;
      if (que.globalconfig.ssl) que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      else que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      que.runtest = Que.rows[0].key.queues.runtest;
      return que;
    }

  }
}
