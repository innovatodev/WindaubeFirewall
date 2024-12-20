using System.Net;

namespace WindaubeFirewall.Connection;

/// <summary>
/// Represents a network connection with its associated metadata, verdict and profile information.
/// </summary>
public class ConnectionModel
{
    required public Guid ProfileID { get; set; }
    required public string ProfileName { get; set; }
    required public byte Verdict { get; set; }
    required public string VerdictReason { get; set; }
    required public string VerdictString { get; set; }
    required public ulong VerdictID { get; set; }
    required public string ConnectionID { get; set; }
    required public ulong ProcessID { get; set; }
    required public ulong ProcessIDKext { get; set; }
    required public string ProcessName { get; set; }
    required public string ProcessPath { get; set; }
    required public string ProcessCommandLine { get; set; }
    required public byte Direction { get; set; }
    required public byte Protocol { get; set; }
    required public int LocalScope { get; set; }
    required public int RemoteScope { get; set; }
    required public int IPVersion { get; set; }
    required public IPAddress LocalIP { get; set; }
    required public ushort LocalPort { get; set; }
    required public IPAddress RemoteIP { get; set; }
    required public ushort RemotePort { get; set; }
    required public DateTime StartDate { get; set; }
    required public bool IsActive { get; set; }
    required public ulong SentBytes { get; set; } = 0;
    required public ulong ReceivedBytes { get; set; } = 0;
    required public byte PayloadLayer { get; set; }
    required public uint PayloadSize { get; set; }
    required public bool IsDNS { get; set; }
    public byte[]? Payload { get; set; }
    public DateTime? EndDate { get; set; }
    public bool IsAnycast { get; set; } = false;
    public string Country { get; set; } = string.Empty;
    public string ASN { get; set; } = string.Empty;
    public string Organization { get; set; } = string.Empty;

    public override string ToString()
    {
        var baseInfo = $"{LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} [{ProcessID}={ProcessName}]";

        var additionalInfo = new List<string>();

        // Add payload info
        if (PayloadSize > 0)
        {
            additionalInfo.Add($"PS:{PayloadSize} PL:{PayloadLayer}");
        }

        // Add verdict info if present
        if (!string.IsNullOrEmpty(VerdictString))
        {
            additionalInfo.Add($"V:{VerdictString}:{VerdictReason}");
        }

        // Add country info if present
        if (!string.IsNullOrEmpty(Country))
        {
            additionalInfo.Add($"CN:{Country}");
        }

        // Add ProfileName info if present
        if (!string.IsNullOrEmpty(ProfileName))
        {
            additionalInfo.Add($"ProName:{ProfileName}");
        }

        return additionalInfo.Count > 0
            ? $"{baseInfo}|{string.Join("|", additionalInfo)}"
            : baseInfo;
    }

    /// <summary>
    /// Generates a unique connection identifier based on protocol, direction and endpoint information.
    /// </summary>
    public static string GenerateConnectionID(byte protocol, byte direction, IPAddress localIP, ushort localPort, IPAddress remoteIP, ushort remotePort)
    {
        string input = $"{protocol}-{direction}_{localIP}:{localPort}-{remoteIP}:{remotePort}";
        return input;
    }
}

/// <summary>
/// Represents a new connection event from the network driver.
/// Contains initial connection information needed for verdict processing.
/// </summary>
public class ConnectionEvent
{
    required public ulong ID;
    required public ulong ProcessID;
    required public byte Direction;
    required public byte Protocol;
    required public IPAddress LocalIP;
    required public IPAddress RemoteIP;
    required public ushort LocalPort;
    required public ushort RemotePort;
    required public byte PayloadLayer;
    required public uint PayloadSize;
    public byte[]? Payload;

    public override string ToString()
    {
        var baseInfo = $"{LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} {ProcessID}";

        var additionalInfo = new List<string>();

        // Add payload info
        if (PayloadSize > 0)
        {
            additionalInfo.Add($"PS:{PayloadSize} Layer:{PayloadLayer}");
        }

        return additionalInfo.Count > 0
            ? $"{baseInfo} | {string.Join(" | ", additionalInfo)}"
            : baseInfo;
    }
}

/// <summary>
/// Represents a connection termination event from the network driver.
/// </summary>
public class ConnectionEndEvent
{
    required public int ProcessID;
    required public byte Direction;
    required public byte Protocol;
    required public IPAddress LocalIP;
    required public IPAddress RemoteIP;
    required public ushort LocalPort;
    required public ushort RemotePort;
    public override string ToString()
    {
        return $"{LocalIP}:{LocalPort} - {RemoteIP}:{RemotePort} {StringConverters.ProtocolToString(Protocol)} {StringConverters.DirectionToString(Direction)} {ProcessID}";
    }
}
