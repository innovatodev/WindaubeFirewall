using System.Net;

namespace WindaubeFirewall.Network;

public class NetworkTable
{
    public static List<NetworkTableTCP4>? NetworkTableTcp4Active { get; set; }
    public static List<NetworkTableTCP6>? NetworkTableTcp6Active { get; set; }
    public static List<NetworkTableUDP4>? NetworkTableUdp4Active { get; set; }
    public static List<NetworkTableUDP6>? NetworkTableUdp6Active { get; set; }

    public static List<NetworkTableTCP4>? NetworkTableTcp4Cache { get; set; }
    public static List<NetworkTableTCP6>? NetworkTableTcp6Cache { get; set; }
    public static List<NetworkTableUDP4>? NetworkTableUdp4Cache { get; set; }
    public static List<NetworkTableUDP6>? NetworkTableUdp6Cache { get; set; }
}

public class NetworkTableTCP4
{
    public string Protocol { get; } = "TCP4";
    required public uint State { get; set; }
    required public IPAddress LocalAddr { get; set; }
    required public ushort LocalPort { get; set; }
    required public IPAddress RemoteAddr { get; set; }
    required public ushort RemotePort { get; set; }
    required public uint OwningPid { get; set; }
}

public class NetworkTableTCP6
{
    public string Protocol { get; } = "TCP6";
    required public uint State { get; set; }
    required public IPAddress LocalAddr { get; set; }
    required public ushort LocalPort { get; set; }
    required public IPAddress RemoteAddr { get; set; }
    required public ushort RemotePort { get; set; }
    required public uint OwningPid { get; set; }
}

public class NetworkTableUDP4
{
    public string Protocol { get; } = "UDP4";
    required public IPAddress LocalAddr { get; set; }
    required public ushort LocalPort { get; set; }
    required public uint OwningPid { get; set; }
}

public class NetworkTableUDP6
{
    public string Protocol { get; } = "UDP6";
    required public IPAddress LocalAddr { get; set; }
    required public ushort LocalPort { get; set; }
    required public uint OwningPid { get; set; }
}
