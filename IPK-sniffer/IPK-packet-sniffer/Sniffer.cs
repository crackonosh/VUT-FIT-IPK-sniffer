using System;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace IPK_packet_sniffer
{
  public static class Sniffer
  {
    /// <summary>
    /// Holds instance of device we are listening on
    /// </summary>
    private static LibPcapLiveDevice Device { get; set; }

    /// <summary>
    /// Options for filter
    /// </summary>
    private static Options Options { get; set; }

    /// <summary>
    /// Counter for desired number of packets to sniff
    /// </summary>
    private static int _packetCounter;


    /// <summary>
    /// Lists all available devices we can listen on on this machine
    /// </summary>
    public static void ListAvailableDevices()
    {
      var devices = CaptureDeviceList.Instance;
      if (devices.Count < 1)
      {
        Console.WriteLine("No devices found when listing, exiting...");
        Environment.Exit(ReturnCodes.NoDevicesFound);
      }

      foreach (var dev in devices)
      {
        Console.WriteLine(dev.Name);
      }

      Environment.Exit(ReturnCodes.Success);
    }

    /// <summary>
    /// Setups basic things and starts capturing packets
    /// </summary>
    /// <param name="o">Options from commandline arguments</param>
    public static void SniffPackets(Options o)
    {
      // save options
      Options = o;

      // check if passed device on -i flag is valid interface
      CheckInterface(o.Interface);

      try
      {
        // add basic method that should run on captured packet and open
        Device.OnPacketArrival += Device_OnPacketArrival;
        Device.Open(DeviceMode.Promiscuous, 100);
        
        // setup filter for capturing packets
        var filter = ConstructFilter();
        Device.Filter = filter;
        
        // start capturing packets
        Device.Capture();
      }
      catch (Exception e)
      {
        Console.WriteLine("Encountered error when trying to capture packets.");
        Console.WriteLine(e);
        Environment.Exit(ReturnCodes.InternalError);
      }
    }

    /// <summary>
    /// Constructs filter for capturing packets depending on options
    /// </summary>
    /// <returns>String representing filter for SharpPcap library</returns>
    private static string ConstructFilter()
    {
      var filter = "ip and ip6";
      if (!Options.ArpOnly && !Options.IcmpOnly && !Options.TcpOnly && Options.PortNumber == null && !Options.UdpOnly)
      {
        filter += " or tcp or icmp or icmp6 or udp or arp";
        return filter;
      }

      if (Options.PortNumber != null)
      {
        if (Options.ArpOnly || Options.IcmpOnly)
        {
          Console.WriteLine("Cannot have port number for ARP/ICMP, corresponding flags are ignored.");
          if (!Options.TcpOnly && !Options.UdpOnly)
          {
            filter += " or tcp or udp and port " + Options.PortNumber;
            return filter;
          }
        }

        if (Options.TcpOnly) filter += " or tcp";
        if (Options.UdpOnly) filter += " or udp";
        filter += " and port " + Options.PortNumber;
        return filter;
      }

      if (Options.TcpOnly) filter += " or tcp";
      if (Options.UdpOnly) filter += " or udp";
      if (Options.IcmpOnly) filter += " or icmp or icmp6";
      if (Options.ArpOnly) filter += " or arp";
      return filter;
    }

    /// <summary>
    /// Checks whether given interface name is among devices and if so sets it
    /// to Device variable, otherwise exits with corresponding exit code
    /// </summary>
    /// <param name="interfaceName">Name of interface we are looking for</param>
    private static void CheckInterface(string interfaceName)
    {
      // get all devices
      var devices = CaptureDeviceList.Instance;

      // find index of desired interface
      var index = 0;
      foreach (var d in devices)
      {
        if (interfaceName.Equals(d.Name)) break;
        index++;
      }

      // check that interface was found
      if (index == devices.Count)
      {
        Console.WriteLine("Desired interface was not found, exiting...");
        Environment.Exit(ReturnCodes.InvalidInterface);
      }

      // save interface to Sniffer.Device variable
      Device = devices[index] as LibPcapLiveDevice;
    }

    /// <summary>
    /// Resolves DateTime into format that is specified in task's info
    /// </summary>
    /// <param name="time">DateTime representing captured packet</param>
    /// <returns>Formatted time as string</returns>
    private static string ResolveTime(DateTime time)
    {
      if (time.Kind == DateTimeKind.Utc)
      {
        time = TimeZoneInfo.ConvertTime(time, TimeZoneInfo.Local);
      }

      var tz = TimeZoneInfo.Local.BaseUtcOffset.ToString()[..5];
      var year = time.Year;
      var month = time.Month.ToString().Length == 1 ? "0" + time.Month : time.Month.ToString();
      var day = time.Day.ToString().Length == 1 ? "0" + time.Day : time.Day.ToString();
      var hour = time.Hour.ToString().Length == 1 ? "0" + time.Hour : time.Hour.ToString();
      var minute = time.Minute.ToString().Length == 1 ? "0" + time.Minute : time.Minute.ToString();
      var second = time.Second.ToString().Length == 1 ? "0" + time.Second : time.Second.ToString();
      var millisecond = time.Millisecond;

      var tmp = new StringBuilder().AppendFormat(
        "{0}-{1}-{2}T{3}:{4}:{5}.{6}+{7} ",
        year, month, day, hour, minute, second, millisecond, tz
      );

      return tmp.ToString();
    }

    /// <summary>
    /// This function runs every time we capture a packets and depending of
    /// packet's type chooses it's action
    /// </summary>
    /// <param name="sender">???</param>
    /// <param name="e">Contains info about Device and Packet</param>
    private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
      // skip everything that isn't on ethernet link layer
      if (e.Packet.LinkLayerType != LinkLayers.Ethernet) return;
      
      // basic preparations
      var time = ResolveTime(e.Packet.Timeval.Date);
      var len = e.Packet.Data.Length;
      var parsedPacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
      var arpPacket = parsedPacket.PayloadPacket as ArpPacket;

      // check if normal or arp packet
      if (!(parsedPacket.PayloadPacket is IPPacket packet))
      {
        if (arpPacket == null)
        {
          Console.WriteLine("Encountered unspecified error when trying to process packet, exiting...");
          Environment.Exit(ReturnCodes.InternalError);
        }
        else
          Printer.PrintArpPacket(arpPacket, e.Packet.Data, time, len);
      }
      else
      {
        switch (packet.Protocol)
        {
          case ProtocolType.Tcp:
          case ProtocolType.Udp:
            // write TCP/UDP packet
            if (!Printer.PrintTcpUdpPacket(packet, e.Packet.Data, time, len)) return;
            break;
          case ProtocolType.Icmp:
          case ProtocolType.IcmpV6:
            //write ICMP
            Printer.PrintIcmpPacket(packet, e.Packet.Data, time, len);
            break;
          default:
            // Error unsupported protocol
            Console.WriteLine("Encountered packet with unsupported protocol when trying to process packet, exiting...");
            Environment.Exit(ReturnCodes.InternalError);
            break;
        }
      }

      // add space if we expect another packet and return from function
      if (++_packetCounter != Options.NumberOfPackets)
      {
        Console.WriteLine();
        return;
      }
      
      // close listening on device if it's still open and 
      if (Device is {Opened: true}) Device.Close();
      Environment.Exit(ReturnCodes.Success);
    }
  }
}