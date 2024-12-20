namespace WindaubeFirewall.DnsServer;

/// <summary>
/// Represents a reverse DNS lookup result with PTR records and resolution metadata.
/// Used for translating IP addresses to hostnames.
/// </summary>
public class DnsLookup
{
    /// <summary>The queried domain name or IP address</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>List of resolved PTR records</summary>
    public List<string> PTRRecords { get; set; } = [];

    /// <summary>When the lookup was performed</summary>
    public DateTime Timestamp { get; set; } = DateTime.Now;

    /// <summary>Time-to-live in seconds for caching</summary>
    public int TTL { get; set; }

    /// <summary>Name of resolver that provided the response</summary>
    public string ResolvedBy { get; set; } = string.Empty;

    /// <summary>Resolution time in milliseconds</summary>
    public int ResolvedIn { get; set; } = 0;

    /// <summary>Whether the lookup was blocked</summary>
    public bool Blocked { get; set; } = false;

    /// <summary>What blocked the lookup</summary>
    public string BlockedBy { get; set; } = string.Empty;

    /// <summary>
    /// Gets PTR records as a comma-separated string.
    /// </summary>
    public string PTRRecordsAsString => string.Join(", ", PTRRecords);

    /// <summary>
    /// Parses a raw DNS response into a DnsLookup object.
    /// Extracts PTR records and metadata from the response.
    /// </summary>
    public static DnsLookup Parse(byte[] buffer, string queryDomain)
    {
        var lookup = new DnsLookup { Domain = queryDomain };

        // Skip header (12 bytes) and original query
        int position = 12;
        while (buffer[position] != 0) position += buffer[position] + 1;
        position += 5; // Skip remaining query fields

        // Read answer count from header (bytes 6-7)
        int answers = (buffer[6] << 8) | buffer[7];

        for (int i = 0; i < answers; i++)
        {
            // Parse name reference
            position = DnsResponse.SkipNameReference(buffer, position);

            // Read type and class
            int type = (buffer[position] << 8) | buffer[position + 1];
            position += 4; // Skip type and class

            // Read TTL (4 bytes)
            lookup.TTL = (buffer[position] << 24) | (buffer[position + 1] << 16) |
                        (buffer[position + 2] << 8) | buffer[position + 3];
            position += 4;

            // Read data length
            int dataLength = (buffer[position] << 8) | buffer[position + 1];
            position += 2;

            // Handle PTR records
            if (type == 12) // PTR record
            {
                var ptr = DnsResponse.ReadDomainName(buffer, position);
                lookup.PTRRecords.Add(ptr);
            }

            position += dataLength;
        }

        return lookup;
    }

    public override string ToString()
    {
        var IsBlocked = Blocked ? "BLOCKED" : "ALLOWED";
        return $"{ResolvedBy}: {Domain} ({TTL}) = {IsBlocked} | PTR: {PTRRecordsAsString}";
    }
}
