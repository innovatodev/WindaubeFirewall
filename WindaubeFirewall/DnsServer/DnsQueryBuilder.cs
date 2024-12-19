using System.Net;
using System.Net.Sockets;

namespace WindaubeFirewall.DnsServer;

public static class DnsQueryBuilder
{
    private static int _queryId = 1;

    public static byte[] CreateUDP(string domain, DnsQueryType queryType = DnsQueryType.A)
    {
        var query = new List<byte>();

        // Add header
        var id = (ushort)Interlocked.Increment(ref _queryId);
        query.AddRange(BitConverter.GetBytes(id).Reverse()); // Transaction ID
        query.AddRange([1, 0]); // Flags: standard query
        query.AddRange([0, 1]); // Questions: 1
        query.AddRange([0, 0]); // Answer RRs: 0
        query.AddRange([0, 0]); // Authority RRs: 0
        query.AddRange([0, 0]); // Additional RRs: 0

        // Add domain name query
        foreach (var label in domain.Split('.'))
        {
            query.Add((byte)label.Length);
            query.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }
        query.Add(0); // Root label

        // Add query type (A=1 or AAAA=28) and class (IN = 1)
        query.AddRange([0, (byte)queryType, 0, 1]);

        return [.. query];
    }

    public static byte[] CreateDOH(string domain, string dnsDomain, DnsQueryType queryType = DnsQueryType.A)
    {
        return CreateUDP(domain, queryType);
    }

    public static byte[] CreateDOT(string domain, DnsQueryType queryType = DnsQueryType.A)
    {
        return CreateUDP(domain, queryType);
    }

    public static byte[] CreateFromExisting(byte[] originalQuery)
    {
        // Ensure this method correctly preserves the original transaction ID and query structure.
        var query = new List<byte>();
        query.AddRange(originalQuery.Take(12)); // Copy header

        // Extract domain from the query
        int position = 12;
        while (position < originalQuery.Length && originalQuery[position] != 0)
        {
            int length = originalQuery[position];
            query.AddRange(originalQuery.Skip(position).Take(length + 1));
            position += length + 1;
        }
        query.Add(0); // Root label

        // Add query type and class from original
        query.AddRange(originalQuery.Skip(position + 1).Take(4));

        return [.. query];
    }

    public static byte[] CreateResponse(byte[] originalQuery, DnsResponse dnsResponse)
    {
        var responsePacket = new List<byte>();

        // Copy transaction ID and set response flags
        responsePacket.AddRange(originalQuery.Take(2));
        responsePacket.AddRange([0x81, 0x80]); // Response flags

        // Add counts
        responsePacket.AddRange([0, 1]); // Questions: 1
        responsePacket.AddRange(BitConverter.GetBytes((ushort)(dnsResponse.IPs.Count + dnsResponse.CNames.Count)).Reverse());
        responsePacket.AddRange([0, 0]); // Authority RRs: 0
        responsePacket.AddRange([0, 0]); // Additional RRs: 0

        // Copy original query
        int queryLen = 0;
        for (int i = 12; i < originalQuery.Length; i++)
        {
            queryLen++;
            if (originalQuery[i] == 0)
            {
                queryLen += 4; // Type and Class
                break;
            }
        }
        responsePacket.AddRange(originalQuery.Skip(12).Take(queryLen));

        // Add CNAME records
        foreach (var cname in dnsResponse.CNames)
        {
            responsePacket.AddRange(originalQuery.Skip(12).TakeWhile(b => b != 0).ToArray().Concat(new byte[] { 0 }));
            responsePacket.AddRange([0, 5]); // Type: CNAME
            responsePacket.AddRange([0, 1]); // Class: IN
            responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());

            var cnameBytes = DnsUtils.EncodeDomainName(cname);
            responsePacket.AddRange(BitConverter.GetBytes((ushort)cnameBytes.Length).Reverse());
            responsePacket.AddRange(cnameBytes);
        }

        // Add A and AAAA records
        foreach (var ip in dnsResponse.IPs)
        {
            responsePacket.AddRange(originalQuery.Skip(12).TakeWhile(b => b != 0).ToArray().Concat(new byte[] { 0 }));

            if (ip.Contains(':')) // IPv6
            {
                responsePacket.AddRange([0, 28]); // Type: AAAA
                responsePacket.AddRange([0, 1]); // Class: IN
                responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());
                responsePacket.AddRange([0, 16]); // Length: 16 bytes

                // Convert IPv6 string to bytes using IPAddress class
                var ipBytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
                responsePacket.AddRange(ipBytes);
            }
            else // IPv4
            {
                responsePacket.AddRange([0, 1]); // Type: A
                responsePacket.AddRange([0, 1]); // Class: IN
                responsePacket.AddRange(BitConverter.GetBytes((uint)dnsResponse.TTL).Reverse());
                responsePacket.AddRange([0, 4]); // Length: 4 bytes
                responsePacket.AddRange(ip.Split('.').Select(byte.Parse));
            }
        }

        return [.. responsePacket];
    }

    public static byte[] CreatePTRResponse(byte[] originalQuery, DnsLookup dnsLookup)
    {
        var responsePacket = new List<byte>();

        // Copy transaction ID and set response flags
        responsePacket.AddRange(originalQuery.Take(2));
        responsePacket.AddRange([0x81, 0x80]); // Response flags

        // Add counts
        responsePacket.AddRange([0, 1]); // Questions: 1
        responsePacket.AddRange(BitConverter.GetBytes((ushort)dnsLookup.PTRRecords.Count).Reverse());
        responsePacket.AddRange([0, 0]); // Authority RRs: 0
        responsePacket.AddRange([0, 0]); // Additional RRs: 0

        // Copy original query
        int queryLen = 0;
        for (int i = 12; i < originalQuery.Length; i++)
        {
            queryLen++;
            if (originalQuery[i] == 0)
            {
                queryLen += 4; // Type and Class
                break;
            }
        }
        responsePacket.AddRange(originalQuery.Skip(12).Take(queryLen));

        // Add PTR records
        foreach (var ptr in dnsLookup.PTRRecords)
        {
            responsePacket.AddRange(originalQuery.Skip(12).TakeWhile(b => b != 0).ToArray().Concat(new byte[] { 0 }));
            responsePacket.AddRange([0, 12]); // Type: PTR
            responsePacket.AddRange([0, 1]); // Class: IN
            responsePacket.AddRange(BitConverter.GetBytes((uint)dnsLookup.TTL).Reverse());

            var ptrBytes = DnsUtils.EncodeDomainName(ptr);
            responsePacket.AddRange(BitConverter.GetBytes((ushort)ptrBytes.Length).Reverse());
            responsePacket.AddRange(ptrBytes);
        }

        return [.. responsePacket];
    }
}
