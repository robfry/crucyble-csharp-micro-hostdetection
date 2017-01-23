using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using FIDO.HostDetection.FIDO.Support.ErrorHandling;
using FIDO.HostDetection.FIDO.Support.FidoDB;
using FIDO.HostDetection.FIDO.Support.Rest;
using Newtonsoft.Json;

namespace FIDO.HostDetection.FIDO.Support.GeoIP
{
  public class GeoIpLookup
  {
    public GeoIpObject.Location GetLookup(List<string> dstip)
    {
      Console.WriteLine(@"Running GEO IP lookup.");
      var request = "http://100.127.241.104:8080/json/" + dstip[0];
      Thread.Sleep(750);
      var alertRequest = (HttpWebRequest) WebRequest.Create(request);
      alertRequest.Method = "GET";

      try
      {
        var getRest = new Fido_Rest_Connection();
        var stringreturn = getRest.RestCall(alertRequest);
        if (string.IsNullOrEmpty(stringreturn)) return null;
        var geoReturn = JsonConvert.DeserializeObject<GeoIpObject.Location>(stringreturn);
        if (geoReturn != null)
        {
          return geoReturn;
        }
        Console.WriteLine(@"Finished processing GEO IP lookup.");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in GEO IP lookup with getting json:" + e);
      }
      return null;
    }

    public static FidoReturnValues FindIP(FidoReturnValues lFidoReturnValues)
    {

      if (lFidoReturnValues.DstIP.Any())
      {
        lFidoReturnValues.Location = new GeoIpObject.Location();
        var locret = new GeoIpLookup();
        lFidoReturnValues.Location = locret.GetLookup(lFidoReturnValues.DstIP);
        if (lFidoReturnValues.location == null && lFidoReturnValues.Location != null)
        {
          lFidoReturnValues.location = new[] { lFidoReturnValues.Location.longitude, lFidoReturnValues.Location.latitude };
        }
      }
      return lFidoReturnValues;
    }


  }
}
