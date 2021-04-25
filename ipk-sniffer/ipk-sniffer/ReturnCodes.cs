namespace IPK_sniffer
{
  /// <summary>
  /// Class containing return codes for different outcomes
  /// </summary>
  public class ReturnCodes
  {
    /// <summary>
    /// If program ended successfully 
    /// </summary>
    public const int Success = 0;

    /// <summary>
    /// If program takes invalid argument from commandline
    /// </summary>
    public const int InvalidArguments = 1;

    /// <summary>
    /// If given interface is not found in listed devices
    /// </summary>
    public const int InvalidInterface = 2;

    /// <summary>
    /// If given port is not in <1, 65535> range
    /// </summary>
    public const int InvalidPortNumber = 3;

    /// <summary>
    /// If no device was found when listing available devices in sniffer
    /// </summary>
    public const int NoDevicesFound = 4;

    /// <summary>
    /// If internal error occured
    /// </summary>
    public const int InternalError = 99;
  }
}