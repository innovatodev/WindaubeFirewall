using System.Net;
using System.Net.Sockets;

namespace WindaubeFirewall.DnsServer;

/// <summary>
/// Represents a DNS response with resolved addresses, metadata, and blocking information.
/// Handles parsing of DNS response packets and tracking of resolution details.
/// </summary>
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

    /// <summary>
    /// Parses a raw DNS response packet into a structured DnsResponse object.
    /// </summary>
    /// <param name="buffer">Raw DNS response packet</param>
    /// <param name="queryDomain">Original queried domain name</param>
    /// <returns>Parsed DNS response</returns>
    public static DnsResponse Parse(byte[] buffer, string queryDomain)
    {
        var response = new DnsResponse { Domain = queryDomain };

        // DNS header is always 12 bytes, followed by the query section
        int position = 12;

        // Skip the original query name by following length bytes until root label (0)
        while (buffer[position] != 0) position += buffer[position] + 1;
        position += 5; // Skip: root label (1) + query type (2) + query class (2)

        // Get number of answer records from header
        int answers = (buffer[6] << 8) | buffer[7];

        // Process each answer record
        for (int i = 0; i < answers; i++)
        {
            // Handle DNS name compression and skip name field
            position = SkipNameReference(buffer, position);

            // Parse record type and class (2 bytes each)
            int type = (buffer[position] << 8) | buffer[position + 1];
            position += 4;

            // Parse TTL (32-bit value)
            response.TTL = (buffer[position] << 24) | (buffer[position + 1] << 16) |
                          (buffer[position + 2] << 8) | buffer[position + 3];
            position += 4;

            // Get length of record data
            int dataLength = (buffer[position] << 8) | buffer[position + 1];
            position += 2;

            // Handle different record types
            switch (type)
            {
                case 1: // A record (IPv4)
                    if (dataLength == 4)
                    {
                        var ip = $"{buffer[position]}.{buffer[position + 1]}.{buffer[position + 2]}.{buffer[position + 3]}";
                        response.IPs.Add(ip);
                        response.IPv4Addresses.Add(ip);
                    }
                    break;

                case 28: // AAAA record (IPv6)
                    if (dataLength == 16)
                    {
                        try
                        {
                            var ipBytes = new byte[16];
                            Array.Copy(buffer, position, ipBytes, 0, 16);
                            var ip = new IPAddress(ipBytes).ToString();
                            response.IPs.Add(ip);
                            response.IPv6Addresses.Add(ip);
                        }
                        catch (FormatException)
                        {
                            // Skip invalid IPv6 addresses
                        }
                    }
                    break;

                case 5: // CNAME record
                    var cname = ReadDomainName(buffer, position);
                    response.CNames.Add(cname);
                    response.CNAMEs.Add(cname);
                    break;

                case 12: // PTR record
                    var ptr = ReadDomainName(buffer, position);
                    response.PTRRecords.Add(ptr);
                    break;
            }

            position += dataLength;
        }

        return response;
    }

    /// <summary>
    /// Determines if a response indicates blocking by the upstream resolver.
    /// </summary>
    /// <param name="response">The DNS response to check</param>
    /// <param name="buffer">Raw response buffer</param>
    /// <param name="blockDetectionType">Method to use for detecting blocks</param>
    /// <returns>True if response indicates blocking</returns>
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

    /// <summary>
    /// Reads a domain name from a DNS packet, handling compression pointers.
    /// </summary>
    /// <param name="buffer">Raw DNS packet data</param>
    /// <param name="position">Starting position in buffer</param>
    /// <returns>Decoded domain name</returns>
    /// <remarks>
    /// Handles DNS name compression (RFC 1035 section 4.1.4):
    /// - Single byte length followed by that many bytes for a label
    /// - Two bytes starting with bits 11 indicate a compression pointer
    /// - Zero byte indicates end of domain name
    /// </remarks>
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

    /// <summary>
    /// Advances past a domain name in a DNS packet, handling compression.
    /// </summary>
    /// <param name="buffer">Raw DNS packet data</param>
    /// <param name="position">Starting position in buffer</param>
    /// <returns>Position after the domain name</returns>
    /// <remarks>
    /// Similar to ReadDomainName but only skips the data without decoding.
    /// Used for efficient packet parsing when name content isn't needed.
    /// </remarks>
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
