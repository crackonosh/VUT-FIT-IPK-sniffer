using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace IPK_packet_sniffer
{
  public static class Sniffer
  {
    private static LibPcapLiveDevice Device { get; set; }

    private static Options Options { get; set; }

    private static int _packetCounter;


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

    public static void SniffPackets(Options o)
    {
      // save options
      Options = o;

      // check if passed device on -i flag is valid interface
      CheckInterface(o.Interface);

      try
      {
        Device.OnPacketArrival += Device_OnPacketArrival;
        Device.Open(DeviceMode.Promiscuous, 100);
        var filter = ConstructFilter();
        Device.Filter = filter;
        Device.Capture();
      }
      catch (Exception e)
      {
        Console.WriteLine("Encountered error when trying to capture packets.");
        Console.WriteLine(e);
        Environment.Exit(ReturnCodes.InternalError);
      }
    }

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

    private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
      if (e.Packet.LinkLayerType != LinkLayers.Ethernet) return;
      
      var time = ResolveTime(e.Packet.Timeval.Date);
      var len = e.Packet.Data.Length;
      var parsedPacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
      var arpPacket = parsedPacket.PayloadPacket as ArpPacket;

      if (!(parsedPacket.PayloadPacket is IPPacket packet))
      {
        if (arpPacket == null)
        {
          Console.WriteLine("Encountered unspecified error when trying to process packet, exiting...");
          Environment.Exit(ReturnCodes.InternalError);
        }
        else
          PrintArpPacket(arpPacket, e.Packet.Data, time, len);
      }
      else
      {
        switch (packet.Protocol)
        {
          case ProtocolType.Tcp:
          case ProtocolType.Udp:
            // write TCP/UDP packet
            if (!PrintTcpUdpPacket(packet, e.Packet.Data, time, len)) return;
            break;
          case ProtocolType.Icmp:
          case ProtocolType.IcmpV6:
            //write ICMP
            PrintIcmpPacket(packet, e.Packet.Data, time, len);
            break;
          default:
            // Error unsupported protocol
            Console.WriteLine("Encountered packet with unsupported protocol when trying to process packet, exiting...");
            Environment.Exit(ReturnCodes.InternalError);
            break;
        }
      }

      if (++_packetCounter != Options.NumberOfPackets)
      {
        Console.WriteLine();
        return;
      }
      if (Device is {Opened: true}) Device.Close();
      Environment.Exit(ReturnCodes.Success);
    }

    private static bool PrintTcpUdpPacket(IPPacket packet, IEnumerable<byte> data, string time, int length)
    {
      if (!(packet.PayloadPacket is UdpPacket payloadPacket)) return false;
      
      Console.WriteLine(
        "[{0}] {1}{2} : {3} > {4} : {5}, length {6} bytes",
        packet.Protocol.ToString().ToUpper(), time,
        packet.SourceAddress, payloadPacket.SourcePort,
        packet.DestinationAddress, payloadPacket.DestinationPort,
        length
      );
      PrintData(data);
      return true;
    }

    private static void PrintIcmpPacket(IPPacket packet, IEnumerable<byte> data, string time, int length)
    {
      Console.WriteLine(
        "[{0}] {1}{2} > {3}, length {4} bytes",
        packet.Protocol, time, packet.SourceAddress, packet.DestinationAddress, length
      );
      PrintData(data);
    }

    private static void PrintArpPacket(ArpPacket packet, IEnumerable<byte> data, string time, int length)
    {
      Console.WriteLine(
        "[{0}] {1}{2} > {3} , length {4} bytes",
        "ARP", time,
        packet.SenderProtocolAddress,
        packet.TargetProtocolAddress,
        length
      );
      PrintData(data);
    }

    private static void PrintData(IEnumerable<byte> data)
    {
      var hex = new StringBuilder();
      var ascii = new StringBuilder();

      // fill hex and ascii strings
      foreach (var t in data)
      {
        hex.Append(t.ToString("X").PadLeft(2, '0'));
        if (t >= 0x21 && t <= 0x7e)
          ascii.Append(Encoding.ASCII.GetString(new[] {t}));
        else
          ascii.Append('.');
      }

      var hexArray = new List<string>();
      var asciiArray = new List<string>();

      // helping variable for filling hex/ascii array and restructuring hex array
      var tmp = new StringBuilder();

      for (var i = 0; i < hex.Length; i++)
      {
        tmp.Append(hex[i]);
        if (i + 1 == hex.Length)
        {
          hexArray.Add(tmp.ToString());
          tmp.Clear();
          break;
        }

        if (tmp.Length != 32) continue;
        hexArray.Add(tmp.ToString());
        tmp.Clear();
      }

      for (var i = 0; i < ascii.Length; i++)
      {
        tmp.Append(ascii[i]);
        if (i + 1 == ascii.Length)
        {
          asciiArray.Add(tmp.ToString());
          tmp.Clear();
          break;
        }

        if (tmp.Length != 16) continue;
        asciiArray.Add(tmp.ToString());
        tmp.Clear();
      }


      for (var j = 0; j < hexArray.Count; j++)
      {
        for (var i = 0; i < hexArray[j].Length; i++)
        {
          tmp.Append(hexArray[j][i]);
          if (i % 2 == 1) tmp.Append(' ');
          if (i != 1 && i % 14 == 1) tmp.Append(' ');
        }

        hexArray[j] = tmp.ToString();
        tmp.Clear();
      }

      for (var i = 0; i < hexArray.Count; i++)
      {
        Console.WriteLine("0x{0}0: {1} {2}",
          i.ToString().PadLeft(3, '0'),
          hexArray[i], asciiArray[i]
        );
      }
    }
  }
}