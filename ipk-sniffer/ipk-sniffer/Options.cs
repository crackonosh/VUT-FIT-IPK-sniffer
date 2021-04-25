using CommandLine;

namespace IPK_sniffer
{
  /// <summary>
  /// Class containing options for parsing arguments from commandline
  /// </summary>
  public class Options
  {
    [Option(
      'i',
      "interface",
      HelpText = "Lists all available devices",
      Default = "None"
    )]
    public string Interface { get; set; }

    [Option(
      'p',
      HelpText = "Filters only packets on this port",
      Default = null 
    )]
    public int? PortNumber { get; set; }

    [Option(
      't',
      "tcp",
      HelpText = "Filters that packets are of TCP type"
    )]
    public bool TcpOnly { get; set; }

    [Option(
      'u',
      "udp",
      HelpText = "Filters that packets are of UDP type"
    )]
    public bool UdpOnly { get; set; }

    [Option(
      "arp",
      HelpText = "Filters that packets are of ARP type"
    )]
    public bool ArpOnly { get; set; }

    [Option(
      "icmp",
      HelpText = "Filters that packets are of ICMP type"
    )]
    public bool IcmpOnly { get; set; }

    [Option(
      'n',
      HelpText = "Expected number of packets to catch",
      Default = 1
    )]
    public int NumberOfPackets { get; set; }
  }
}