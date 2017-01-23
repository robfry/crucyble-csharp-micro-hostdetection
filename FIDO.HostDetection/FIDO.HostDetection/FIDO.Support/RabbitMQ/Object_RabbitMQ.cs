

namespace FIDO.HostDetection.FIDO.Support.RabbitMQ
{
  public class Object_RabbitMQ
  {
    public class Event
    {
      public string eventtime { get; set; }
      public string currenttime { get; set; }
      public string uuid { get; set; }
    }

    public class EventMsg
    {
      public Event notification { get; set; }
    }
  }
}
