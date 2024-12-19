using System.Net;
using System.Text.RegularExpressions;
using WindaubeFirewall.Connection;

namespace WindaubeFirewall.Profiles;

public enum TargetType
{
    Any,
    IP,
    CIDR,
    Domain,
    ASN,
    Country,
    Scope
}

public static class CommonPorts
{
    public static readonly Dictionary<string, int> PortMap = new(StringComparer.OrdinalIgnoreCase)
    {
        {"HTTP", 80},
        {"HTTPS", 443},
        {"DNS", 53},
        {"FTP", 21},
        {"SSH", 22},
        {"TELNET", 23},
        {"SMTP", 25},
        {"POP3", 110},
        {"IMAP", 143},
        {"RDP", 3389},
        {"SMB", 445},
        {"MYSQL", 3306},
        {"PGSQL", 5432},
        {"MONGODB", 27017},
        {"REDIS", 6379}
    };
}

public class RuleSet
{
    public string Target { get; set; } = "*";
    public TargetType TargetType { get; set; } = TargetType.Any;
    public string? DomainPattern { get; set; }
    public IPAddress? IPAddress { get; set; }
    public IPNetwork? CIDRRange { get; set; }
    public string? ASNumber { get; set; }
    public string? CountryCode { get; set; }
    public int? Protocol { get; set; }
    public int? PortStart { get; set; }
    public int? PortEnd { get; set; }
    public byte Action { get; set; }  // 0 = block, 1 = allow, 2 = prompt

    public static RuleSet Parse(string rule)
    {
        var parts = rule.Split(' ', 2);
        var result = new RuleSet
        {
            Action = parts[0].ToUpper() switch
            {
                "BLOCK" => 0,
                "ALLOW" => 1,
                "PROMPT" => 2,
                _ => throw new ArgumentException("Invalid action")
            }
        };

        if (parts.Length == 1) return result; // Just action = match all

        var targetAndProtocol = parts[1].Split(' ', 2);
        var target = targetAndProtocol[0];

        // Parse target
        if (target == "*")
        {
            result.TargetType = TargetType.Any;
        }
        else if (IPAddress.TryParse(target, out var ip))
        {
            result.TargetType = TargetType.IP;
            result.IPAddress = ip;
        }
        else if (target.Contains('/') && IPNetwork.TryParse(target, out var cidr))
        {
            result.TargetType = TargetType.CIDR;
            result.CIDRRange = cidr;
        }
        else if (target.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            result.TargetType = TargetType.ASN;
            result.ASNumber = target;
        }
        else if (target.Length == 2 && target.All(char.IsLetter))
        {
            result.TargetType = TargetType.Country;
            result.CountryCode = target.ToUpper();
        }
        else if (target.ToUpper() is "LOCALHOST" or "MULTICAST" or "BROADCAST" or "LAN" or "INTERNET")
        {
            result.TargetType = TargetType.Scope;
            result.Target = target.ToUpper();
        }
        else
        {
            result.TargetType = TargetType.Domain;
            result.DomainPattern = target.Replace("*", ".*");
        }

        // Parse protocol/port if present
        if (targetAndProtocol.Length > 1)
        {
            var protocolPart = targetAndProtocol[1];
            var protocolSplit = protocolPart.Split('/');
            var protocol = protocolSplit[0].ToUpper();

            result.Protocol = protocol switch
            {
                "HOPOPT" => 0,
                "ICMP" => 1,
                "IGMP" => 2,
                "IPV4" => 4,
                "TCP" => 6,
                "UDP" => 17,
                "RDP" => 27,
                "DCCP" => 33,
                "IPV6" => 41,
                "IPV6-FRAG" => 44,
                "ICMPV6" => 58,
                "ENCAPSULATIONHEADER" => 98,
                "UDPLITE" => 136,
                "*" => null,
                _ => int.TryParse(protocol, out var proto) ? proto : throw new ArgumentException("Invalid protocol")
            };

            if (protocolSplit.Length > 1)
            {
                var port = protocolSplit[1];
                if (port.Contains('-'))
                {
                    var ports = port.Split('-');
                    result.PortStart = ParsePort(ports[0]);
                    result.PortEnd = ParsePort(ports[1]);
                }
                else
                {
                    result.PortStart = result.PortEnd = ParsePort(port);
                }
            }
        }

        return result;
    }

    private static int ParsePort(string port)
    {
        if (CommonPorts.PortMap.TryGetValue(port, out var commonPort))
            return commonPort;
        return int.Parse(port);
    }

    public bool Matches(ConnectionModel connection)
    {
        // Protocol check
        if (Protocol.HasValue && Protocol.Value != connection.Protocol)
            return false;

        // Port check (considering multicast special case)
        if (PortStart.HasValue)
        {
            var portToCheck = (IPAddresses.IsMulticastAddress(connection.RemoteIP) ||
                             IPAddresses.IsMulticastAddress(connection.LocalIP)) &&
                             connection.Direction == 1
                ? connection.LocalPort
                : connection.RemotePort;

            if (portToCheck < PortStart || portToCheck > PortEnd)
                return false;
        }

        // Target check
        return TargetType switch
        {
            TargetType.Any => true,
            TargetType.IP => IPAddress?.Equals(connection.RemoteIP) ?? false,
            TargetType.CIDR => CIDRRange?.Contains(connection.RemoteIP) ?? false,
            // Add Domain check
            TargetType.ASN => connection.ASN == ASNumber,
            TargetType.Country => connection.Country.Equals(CountryCode, StringComparison.OrdinalIgnoreCase),
            TargetType.Scope => Target.ToUpper() switch
            {
                "LOCALHOST" => connection.RemoteScope == 0,
                "MULTICAST" => connection.RemoteScope == 1,
                "BROADCAST" => connection.RemoteScope == 2,
                "LAN" => connection.RemoteScope == 3,
                "INTERNET" => connection.RemoteScope == 4,
                _ => false
            },
            _ => false
        };
    }
}
