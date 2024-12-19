using System.Net;
using System.Net.Sockets;

namespace WindaubeFirewall.DnsServer;

public class DnsResponse
{
    public string Domain { get; set; } = string.Empty;
    public List<string> CNames { get; set; } = [];
    public List<string> IPs { get; set; } = [];
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public int TTL { get; set; }
    public string ResolvedBy { get; set; } = string.Empty;
    public int ResolvedIn { get; set; } = 0;
    public bool Blocked { get; set; } = false;
    public string? BlockedBy { get; set; }
    public string? BlockedReason { get; set; }

    public string IPsAsString => string.Join(", ", IPs);
    public string CNamesAsString => string.Join(", ", CNames);

    public List<string> IPv4Addresses { get; set; } = [];
    public List<string> IPv6Addresses { get; set; } = [];
    public List<string> CNAMEs { get; set; } = [];
    public List<string> PTRRecords { get; set; } = [];

    public bool HasIPAddress => IPv4Addresses.Count > 0 || IPv6Addresses.Count > 0;
    public string? CNAME => CNAMEs.FirstOrDefault();

    public override string ToString()
    {
        var IsBlocked = Blocked ? (BlockedReason != null ? $"BLOCKED ({BlockedReason})" : "BLOCKED") : "ALLOWED";
        return $"{ResolvedBy} {ResolvedIn}ms: {Domain} ({TTL}) = {IsBlocked} | IPs: {IPs.Count} | CNAMEs: {CNames.Count}";
    }

    public static DnsResponse Parse(byte[] buffer, string queryDomain)
    {
        var response = new DnsResponse { Domain = queryDomain };

        // Skip header (12 bytes) and original query
        int position = 12;
        while (buffer[position] != 0) position += buffer[position] + 1;
        position += 5; // Skip remaining query fields

        // Read answer count from header (bytes 6-7)
        int answers = (buffer[6] << 8) | buffer[7];

        for (int i = 0; i < answers; i++)
        {
            // Parse name reference
            position = SkipNameReference(buffer, position);

            // Read type and class
            int type = (buffer[position] << 8) | buffer[position + 1];
            position += 4; // Skip type and class

            // Read TTL (4 bytes)
            response.TTL = (buffer[position] << 24) | (buffer[position + 1] << 16) |
                          (buffer[position + 2] << 8) | buffer[position + 3];
            position += 4;

            // Read data length
            int dataLength = (buffer[position] << 8) | buffer[position + 1];
            position += 2;

            // Handle records
            if (type == 1 && dataLength == 4) // A record
            {
                var ip = $"{buffer[position]}.{buffer[position + 1]}.{buffer[position + 2]}.{buffer[position + 3]}";
                response.IPs.Add(ip);
                response.IPv4Addresses.Add(ip);
            }
            else if (type == 28 && dataLength == 16) // AAAA record
            {
                try
                {
                    var ipBytes = new byte[16];
                    Array.Copy(buffer, position, ipBytes, 0, 16);
                    var ip = new System.Net.IPAddress(ipBytes).ToString();
                    response.IPs.Add(ip);
                    response.IPv6Addresses.Add(ip);
                }
                catch (FormatException)
                {
                    // Handle invalid IPv6 address format if necessary
                }
            }
            else if (type == 5) // CNAME record
            {
                var cname = ReadDomainName(buffer, position);
                response.CNames.Add(cname);
                response.CNAMEs.Add(cname);
            }
            else if (type == 12) // PTR record
            {
                var ptr = DnsResponse.ReadDomainName(buffer, position);
                response.PTRRecords.Add(ptr);
            }

            position += dataLength;
        }

        return response;
    }

    public static bool IsBlockedUpstream(DnsResponse response, byte[] buffer, ResolverBlockedIfOptions blockDetectionType)
    {
        if (blockDetectionType == ResolverBlockedIfOptions.Disabled)
            return false;

        var rcode = buffer[3] & 0x0F;
        var answerCount = (buffer[6] << 8) | buffer[7];
        var authorityCount = (buffer[8] << 8) | buffer[9];
        var additionalCount = (buffer[10] << 8) | buffer[11];

        switch (blockDetectionType)
        {
            case ResolverBlockedIfOptions.Refused:
                return rcode == 5; // RcodeRefused

            case ResolverBlockedIfOptions.ZeroIP:
                if (rcode != 0) // RcodeSuccess
                    return false;

                if (response.IPs.Count == 0)
                    return false; // Must have IPs to check for zero IPs

                return response.IPs.All(ip =>
                {
                    if (IPAddress.TryParse(ip, out var addr))
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetwork)
                            return ip == "0.0.0.0";
                        else
                            return ip == "::";
                    }
                    return false;
                });

            case ResolverBlockedIfOptions.Empty:
                // Only consider a response blocked if it has no IPs AND no CNAMEs
                return (rcode == 3 && // RcodeNameError (NXDOMAIN)
                       answerCount == 0 &&
                       authorityCount == 0 &&
                       additionalCount == 0) ||
                       (response.IPs.Count == 0 && response.CNames.Count == 0);

            default:
                return false;
        }
    }

    public static string ReadDomainName(byte[] buffer, int position)
    {
        var domain = new System.Text.StringBuilder();
        var currentPosition = position;

        while (currentPosition < buffer.Length)
        {
            if (buffer[currentPosition] == 0)
            {
                break;
            }
            else if ((buffer[currentPosition] & 0xC0) == 0xC0)
            {
                var offset = ((buffer[currentPosition] & 0x3F) << 8) | buffer[currentPosition + 1];
                if (domain.Length > 0) domain.Append('.');
                domain.Append(ReadDomainName(buffer, offset));
                break;
            }
            else
            {
                int length = buffer[currentPosition++];
                if (domain.Length > 0) domain.Append('.');
                for (int i = 0; i < length; i++)
                {
                    domain.Append((char)buffer[currentPosition++]);
                }
            }
        }
        return domain.ToString();
    }

    public static int SkipNameReference(byte[] buffer, int position)
    {
        while (position < buffer.Length)
        {
            if (buffer[position] == 0)
            {
                return position + 1;
            }
            else if ((buffer[position] & 0xC0) == 0xC0)
            {
                return position + 2;
            }
            else
            {
                position += buffer[position] + 1;
            }
        }
        return position;
    }
}
