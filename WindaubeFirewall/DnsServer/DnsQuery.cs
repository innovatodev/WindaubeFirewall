using System.Net;
using System.Net.Sockets;

namespace WindaubeFirewall.DnsServer;

public class DnsQuery
{
    // Informations
    public byte[] RawQuery { get; }
    public IPAddress IpAddress { get; }
    public int Port { get; }
    public DateTime Timestamp { get; }

    // Parsed DNS fields
    public ushort TransactionId { get; set; }
    public bool IsQuery { get; set; }
    public ushort Flags { get; set; }
    public ushort QuestionCount { get; set; }
    public ushort AnswerCount { get; set; }
    public ushort AuthorityCount { get; set; }
    public ushort AdditionalCount { get; set; }
    public string? QueryDomain { get; set; }
    public DnsQueryType QueryType { get; set; }
    public DnsQueryClass QueryClass { get; set; }
    public bool Recurse { get; set; }

    public DnsQuery(byte[] rawQuery, IPEndPoint remoteEndPoint)
    {
        RawQuery = rawQuery;
        IpAddress = remoteEndPoint.Address;
        Port = remoteEndPoint.Port;
        Timestamp = DateTime.UtcNow;
        ParseDnsHeader();
        Recurse = false;
    }

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

    public static bool IsValidQuery(DnsQuery query)
    {
        // Validate query header and content
        if (query.RawQuery.Length < 12)
        {
            Logger.Log($"DnsServerValidation: Query too short ({query.RawQuery.Length} bytes)");
            return false;
        }

        // Must be a standard query (QR=0, OPCODE=0)
        var opcode = (query.Flags >> 11) & 0xF;
        if (!query.IsQuery || opcode != 0)
        {
            Logger.Log($"DnsServerValidation: Invalid query flags - QR:{!query.IsQuery}, OPCODE:{opcode}");
            return false;
        }

        // Must have exactly one question
        if (query.QuestionCount != 1)
        {
            // Reduced logging for excessive question counts
            if (query.QuestionCount > 10)
            {
                Logger.Log($"DnsServerValidation: Excessive question count: {query.QuestionCount}");
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

    private void ParseDnsHeader()
    {
        if (RawQuery.Length < 12) return; // DNS header is 12 bytes

        TransactionId = (ushort)((RawQuery[0] << 8) | RawQuery[1]);
        Flags = (ushort)((RawQuery[2] << 8) | RawQuery[3]);
        IsQuery = (Flags & 0x8000) == 0;
        QuestionCount = (ushort)((RawQuery[4] << 8) | RawQuery[5]);
        AnswerCount = (ushort)((RawQuery[6] << 8) | RawQuery[7]);
        AuthorityCount = (ushort)((RawQuery[8] << 8) | RawQuery[9]);
        AdditionalCount = (ushort)((RawQuery[10] << 8) | RawQuery[11]);
        QueryDomain = DnsUtils.ExtractDomain(RawQuery);
        // Parse Query Type and Class if we have enough data
        if (RawQuery.Length >= 16)
        {
            QueryType = (DnsQueryType)((RawQuery[^4] << 8) | RawQuery[^3]);
            QueryClass = (DnsQueryClass)((RawQuery[^2] << 8) | RawQuery[^1]);
        }
    }
}

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

public enum DnsQueryClass : ushort
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255
}
