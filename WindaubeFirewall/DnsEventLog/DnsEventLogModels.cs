using System.Net;

namespace WindaubeFirewall.DnsEventLog;

public class DnsQueryEventLog
{
    public string QueryName { get; set; } = string.Empty;
    public int QueryType { get; set; }
    public long QueryOptions { get; set; }
    public string ServerList { get; set; } = string.Empty; // Empty
    public int IsNetworkQuery { get; set; }
    public int NetworkQueryIndex { get; set; }
    public int InterfaceIndex { get; set; }
    public int IsAsyncQuery { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string ProcessCommandLine { get; set; } = string.Empty;
    public Guid ProfileID { get; set; } = Guid.Empty;
    public string ProfileName { get; set; } = string.Empty;
    public DateTime TimeStamp { get; set; }
    public string UID { get; set; } = string.Empty;

    public override string ToString() => $"{ProcessId}={ProcessName}: {QueryName} | QueryType:{QueryType} | Pro:{ProfileName}";
}

public class DnsResponseEventLog
{
    public string QueryName { get; set; } = string.Empty;
    public int QueryType { get; set; }
    public long QueryOptions { get; set; }
    public int QueryStatus { get; set; }
    public string QueryResults { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string ProcessCommandLine { get; set; } = string.Empty;
    public Guid ProfileID { get; set; } = Guid.Empty;
    public string ProfileName { get; set; } = string.Empty;
    public List<IPAddress> IpAddresses { get; set; } = [];
    public Dictionary<string, string> CNames { get; set; } = [];
    public string UID { get; set; } = string.Empty;
    public DateTime TimeStamp { get; set; }

    public override string ToString() => $"{ProcessId}={ProcessName}: {QueryName} | QueryType:{QueryType} | {IpAddresses.Count} IPs, {CNames.Count} CNAMEs | Pro:{ProfileName}";
}
