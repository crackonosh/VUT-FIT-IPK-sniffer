# IPK packet sniffer
### Description
IPK-sniffer is an application that listens to internet communication on specified interface and prints captured packets to _standard output_. It supports capturing/printing of TCP, UDP, ICMP & ARP packets, other types of packet are ignored in code.

Application is written in C# using `.NET Core 3.1`, but newer versions of `.NET` should also support it.

##### Dependencies
- NuGet packages (packages are downloaded and installed during building of program see [Building project](#Building-project)):
  1. [CommandLineParser](https://www.nuget.org/packages/CommandLineParser/) - for parsing arguments from command line
  1. [SharpPcap](https://www.nuget.org/packages/CommandLineParser/) - for listing interfaces and capturing packets

### Building project
To build project we can use this command that downloads dependencies and compiles project into new `build` folder created in _present working directory_:
```
dotnet build ipk-sniffer/ipk-sniffer -c Release -o build -r <RUNTIME>
```
  - where `<RUNTIME>` equals to current platform we want to build for (ex.: `linux-x64`, `osx-x64`,...), in makefile `<RUNTIME>` equals to `linux-x64`

We also can run `make` command which perfroms `clean` (see [Cleaning project](#Cleaning-project) and `build` (is equal to command above) targets specified in makefile.

### Cleaning project
To clean files created after building project we can run following commands:
```
dotnet clean ipk-sniffer/ipk -c Release
rm -rf build
```
  - this removes files created while building project (see [Building project](#Building-project)) and after that removes `build` folder containing compiled files

We also can run `make clean` command which performs those 2 lines mentioned above.

### Running program
If building was successful we are ablo to run our program with this command:
```
sudo ./build/ipk-sniffer {[-i {interface}|--interface {interface}]} {-p port} {[-t|--tcp] [-u|--udp] [--arp] [--icmp]} {-n num}
```
- arguments:
  - `-i {interface}` - name of interface we want to listen on. If no interface is specified or `-i` flag is missing completely we print available devices for listening.
  - `-p port` - captures packets with specified port only
  - `-t` - only TCP packets
  - `-u` - only UDP packets
  - `--arp` - only ARP packets
  - `--icmp` - only ICMP packets
  - `-n num` - number of packets to capture, defaults to 1
We are able to combinate `-t`, `-u`, `--arp`, `--icmp` arguments between each other. If no argument from those 4 is specified it equals to having all 4 present.

