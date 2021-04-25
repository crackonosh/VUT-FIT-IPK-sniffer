using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet;

namespace IPK_packet_sniffer
{
  public static class Printer
  {
    /// <summary>
    /// Print TCP/UDP packet to stdout
    /// </summary>
    /// <param name="packet">Captured packet</param>
    /// <param name="data">Packet data</param>
    /// <param name="time">Formatted time to print</param>
    /// <param name="length">Length of packet</param>
    /// <returns>True if printing was successful, otherwise false</returns>
    public static bool PrintTcpUdpPacket(IPPacket packet, IEnumerable<byte> data, string time, int length)
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

    /// <summary>
    /// Prints ICMP packet to stdout
    /// </summary>
    /// <param name="packet">Captured packet</param>
    /// <param name="data">Packet data</param>
    /// <param name="time">Formatted time to print</param>
    /// <param name="length">Length of packet</param>
    public static void PrintIcmpPacket(IPPacket packet, IEnumerable<byte> data, string time, int length)
    {
      Console.WriteLine(
        "[{0}] {1}{2} > {3}, length {4} bytes",
        packet.Protocol, time, packet.SourceAddress, packet.DestinationAddress, length
      );
      PrintData(data);
    }

    /// <summary>
    /// Prints ARP packet to stdout
    /// </summary>
    /// <param name="packet">Captured packet</param>
    /// <param name="data">Packet data</param>
    /// <param name="time">Formatted time to print</param>
    /// <param name="length">Length of packet</param>
    public static void PrintArpPacket(ArpPacket packet, IEnumerable<byte> data, string time, int length)
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

    /// <summary>
    /// Formats given data to format specified in task's assignment and then
    /// prints it to stdout
    /// </summary>
    /// <param name="data">Data to format and print</param>
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

      // fill hexArray with 32 chars
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

      // fill asciArray with 16 chars
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


      // reformat hexArray so that it has spaces between every 2 chars and after 8 chars
      for (var j = 0; j < hexArray.Count; j++)
      {
        for (var i = 0; i < hexArray[j].Length; i++)
        {
          tmp.Append(hexArray[j][i]);
          if (i % 2 == 1) tmp.Append(' ');
          if (i != 1 && i != 29 && i % 14 == 1) tmp.Append(' ');
        }

        hexArray[j] = tmp.ToString().PadRight(49, ' ');
        tmp.Clear();
      }

      // print result
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