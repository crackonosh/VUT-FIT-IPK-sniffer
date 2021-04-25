using System;
using System.Collections.Generic;
using CommandLine;

namespace IPK_sniffer
{
  internal static class Program
  {
    private static void Main(string[] args)
    {
      // parsing of commandline arguments
      var parser = new Parser();
      parser.ParseArguments<Options>(args)
        .WithParsed((o) =>
        {
          // if no device was selected to listen for -> list all devices
          if (o.Interface.Equals("None"))
          {
            Sniffer.ListAvailableDevices();
          }
          // if port is not null and not in valid range
          else if (o.PortNumber != null && (o.PortNumber > 65535 || o.PortNumber < 1))
          {
            Console.WriteLine("Port number is not in <1, 65535> range, exiting...");
            Environment.Exit(ReturnCodes.InvalidPortNumber);
          }
          // start sniffing
          else
          {
            Sniffer.SniffPackets(o);
            Environment.Exit(ReturnCodes.Success);
          }
        })
        .WithNotParsed(ErrorHandler);
    }

    /// <summary>
    /// Handles errors when parsing arguments
    /// </summary>
    /// <param name="errors">Enumerable containing Errors</param>
    private static void ErrorHandler(IEnumerable<Error> errors)
    {
      var tmpError = "Encountered following error(s) when parsing arguments\n";
      foreach (var e in errors)
      {
        if (e is MissingValueOptionError valErr)
        {
          // if missing value for -i or --interface 
          if (valErr.NameInfo.ShortName == "i")
            Sniffer.ListAvailableDevices();
          // otherwise list parameters that have missing value
          else
          {
            tmpError += "\tparam: " +
                        valErr.NameInfo.NameText +
                        " -> " +
                        valErr.Tag +
                        "\n";
          }
        }
        else
          tmpError += "\t" + e.Tag + "\n";
      }

      Console.WriteLine(tmpError);
      Environment.Exit(ReturnCodes.InvalidArguments);
    }
  }
}