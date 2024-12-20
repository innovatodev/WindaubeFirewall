using System.Net;

namespace WindaubeFirewall.DnsServer;

/// <summary>
/// Represents a DNS query with parsed header fields and query parameters.
/// Provides methods for query validation and inspection.
/// </summary>
public class DnsQuery
{
    /// <summary>Raw DNS query packet data</summary>
    public byte[] RawQuery { get; }

    /// <summary>Source IP address of the query</summary>
    public IPAddress IpAddress { get; }

    /// <summary>Source port of the query</summary>
    public int Port { get; }

    /// <summary>Timestamp when query was received</summary>
    public DateTime Timestamp { get; }

    // DNS header fields
    /// <summary>DNS transaction ID for query/response matching</summary>
    public ushort TransactionId { get; set; }

    /// <summary>Whether this is a query (true) or response (false)</summary>
    public bool IsQuery { get; set; }

    /// <summary>DNS header flags</summary>
    public ushort Flags { get; set; }

    // DNS section counts
    public ushort QuestionCount { get; set; }
    public ushort AnswerCount { get; set; }
    public ushort AuthorityCount { get; set; }
    public ushort AdditionalCount { get; set; }

    // Query details
    public string? QueryDomain { get; set; }
    public DnsQueryType QueryType { get; set; }
    public DnsQueryClass QueryClass { get; set; }
    public bool Recurse { get; set; }

    /// <summary>
    /// Creates a new DNS query from a raw packet and remote endpoint.
    /// </summary>
    public DnsQuery(byte[] rawQuery, IPEndPoint remoteEndPoint)
    {
        RawQuery = rawQuery;
        IpAddress = remoteEndPoint.Address;
        Port = remoteEndPoint.Port;
        Timestamp = DateTime.UtcNow;
        ParseDnsHeader();
        Recurse = false;
    }

    /// <summary>
    /// Creates a new DNS query with specified parameters.
    /// </summary>
    public DnsQuery(DnsQueryType queryType, string domain, IPAddress ipAddress, int port)
    {
        QueryType = queryType;
        QueryDomain = domain;
        IpAddress = ipAddress;
        Port = port;
        Timestamp = DateTime.UtcNow;
        RawQuery = DnsQueryBuilder.CreateUDP(domain, queryType);
        ParseDnsHeader();
        Recurse = false;
    }

    public override string ToString()
    {
        return $"{QueryDomain} {IpAddress}:{Port} " +
               $"{TransactionId} {Flags} " +
               $"{QuestionCount} {AnswerCount} " +
               $"{AuthorityCount} {AdditionalCount} " +
               $"{QueryType} {QueryClass}";
    }

    /// <summary>
    /// Validates a DNS query for correctness and security.
    /// Checks header fields, question count, and query content.
    /// </summary>
    /// <returns>True if query is valid, false otherwise</returns>
    public static bool IsValidQuery(DnsQuery query)
    {
        // DNS header must be at least 12 bytes
        if (query.RawQuery.Length < 12)
        {
            Logger.Log($"DnsServerValidation: Query too short ({query.RawQuery.Length} bytes)");
            return false;
        }

        // Check QR bit (must be 0 for query) and OPCODE (must be 0 for standard query)
        var opcode = (query.Flags >> 11) & 0xF;
        if (!query.IsQuery || opcode != 0)
        {
            Logger.Log($"DnsServerValidation: Invalid query flags - QR:{!query.IsQuery}, OPCODE:{opcode}");
            return false;
        }

        // DNS protocol requires exactly one question in standard queries
        if (query.QuestionCount != 1)
        {
            // Log differently for possible DoS attempts (high question count)
            if (query.QuestionCount > 10)
            {
                Logger.Log($"DnsServerValidation: Possible DoS - excessive question count: {query.QuestionCount}");
            }
            else
            {
                Logger.Log($"DnsServerValidation: Invalid question count: {query.QuestionCount}");
            }
            return false;
        }

        // Must have a valid domain name
        if (string.IsNullOrWhiteSpace(query.QueryDomain))
        {
            Logger.Log("DnsServerValidation: Empty domain name"); // Commented out to reduce noise
            return false;
        }

        // Validate query type (accept all valid DNS types)
        if (!Enum.IsDefined(typeof(DnsQueryType), query.QueryType))
        {
            // Allow unknown query types but log them
            Logger.Log($"DnsServerValidation: Non-standard query type: {query.QueryType} for {query.QueryDomain}");
            return true; // Accept the query anyway
        }

        // Validate query class (IN class is most common)
        if (query.QueryClass != DnsQueryClass.IN)
        {
            Logger.Log($"DnsServerValidation: Invalid query class: {query.QueryClass}");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses the DNS header fields and query section from the raw query data.
    /// </summary>
    /// <remarks>
    /// DNS header format (RFC 1035 section 4.1.1):
    ///                                 1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      ID                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QDCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ANCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    NSCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ARCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// </remarks>
    private void ParseDnsHeader()
    {
        // DNS header structure (12 bytes total):
        // Bytes 0-1:   Transaction ID
        // Bytes 2-3:   Flags
        // Bytes 4-5:   Question count
        // Bytes 6-7:   Answer RR count
        // Bytes 8-9:   Authority RR count
        // Bytes 10-11: Additional RR count

        if (RawQuery.Length < 12) return;

        // Parse each header field
        // Parse header fields (12 bytes total)
        TransactionId = (ushort)((RawQuery[0] << 8) | RawQuery[1]);      // Bytes 0-1: Transaction ID
        Flags = (ushort)((RawQuery[2] << 8) | RawQuery[3]);             // Bytes 2-3: Flags
        IsQuery = (Flags & 0x8000) == 0;                                // QR bit (bit 15)
        QuestionCount = (ushort)((RawQuery[4] << 8) | RawQuery[5]);     // Bytes 4-5: Questions
        AnswerCount = (ushort)((RawQuery[6] << 8) | RawQuery[7]);       // Bytes 6-7: Answer RRs
        AuthorityCount = (ushort)((RawQuery[8] << 8) | RawQuery[9]);    // Bytes 8-9: Authority RRs
        AdditionalCount = (ushort)((RawQuery[10] << 8) | RawQuery[11]); // Bytes 10-11: Additional RRs

        // Parse query section
        QueryDomain = DnsUtils.ExtractDomain(RawQuery);

        // Parse Query Type and Class if we have enough data
        if (RawQuery.Length >= 16)
        {
            QueryType = (DnsQueryType)((RawQuery[^4] << 8) | RawQuery[^3]);
            QueryClass = (DnsQueryClass)((RawQuery[^2] << 8) | RawQuery[^1]);
        }
    }
}

/// <summary>
/// DNS query types as defined in RFC 1035 and subsequent RFCs.
/// </summary>
public enum DnsQueryType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
    HTTPS = 65,
    SVCB = 64,
    OPT = 41,
    CAA = 257,
}

/// <summary>
/// DNS query classes as defined in RFC 1035.
/// IN is the most common class used for Internet data.
/// </summary>
public enum DnsQueryClass : ushort
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255
}
