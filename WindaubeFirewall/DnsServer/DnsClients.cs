using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace WindaubeFirewall.DnsServer;

public static class DnsClients
{
    public static async Task<DnsResponse?> QueryAsyncDNS(DnsQuery query, Resolver resolver, int timeout, CancellationToken token)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var udpClient = new UdpClient(AddressFamily.InterNetworkV6);
        udpClient.Client.DualMode = true;

        try
        {
            var endPoint = new IPEndPoint(resolver.IPAddress, resolver.Port);

            var dnsQuery = DnsQueryBuilder.CreateUDP(
                query.QueryDomain ?? string.Empty,
                query.QueryType
            );

            await udpClient.SendAsync(dnsQuery, dnsQuery.Length, resolver.IPAddress.ToString(), resolver.Port);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);

            var result = await udpClient.ReceiveAsync(cts.Token);
            if (result.Buffer.Length > 12)
            {
                var response = DnsResponse.Parse(result.Buffer, query.QueryDomain ?? string.Empty);
                response.ResolvedBy = resolver.Name;
                if (DnsResponse.IsBlockedUpstream(response, result.Buffer, resolver.BlockedIf))
                {
                    response.Blocked = true;
                    response.BlockedBy = resolver.Name;
                    response.BlockedReason = "BlockedUpstream";
                }
                return response;
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Log($"DnsServerTimeout DNS: {query.QueryDomain} using {resolver.Name}");
            throw; // Rethrow the exception to let TryResolvers handle it
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsServerFail DNS: {query.QueryDomain} using {resolver.Name}: {ex.Message}");
            throw; // Rethrow the exception
        }

        return null;
    }

    public static async Task<DnsResponse?> QueryAsyncDOH(DnsQuery query, Resolver resolver, int timeout, CancellationToken token)
    {
        try
        {
            using var httpClient = new HttpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);

            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            var dnsQuery = DnsQueryBuilder.CreateDOH(
                query.QueryDomain ?? string.Empty,
                resolver.Domain,
                query.QueryType
            );

            var url = resolver.IPAddress.AddressFamily == AddressFamily.InterNetworkV6
                ? $"https://[{resolver.IPAddress}]/dns-query"
                : $"https://{resolver.IPAddress}/dns-query";

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Host = resolver.Domain;
            request.Content = new ByteArrayContent(dnsQuery);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

            var responseMessage = await httpClient.SendAsync(request, cts.Token);
            responseMessage.EnsureSuccessStatusCode();

            var responseBytes = await responseMessage.Content.ReadAsByteArrayAsync(cts.Token);
            if (responseBytes.Length > 12)
            {
                var response = DnsResponse.Parse(responseBytes, query.QueryDomain ?? string.Empty);
                response.ResolvedBy = resolver.Name;
                if (DnsResponse.IsBlockedUpstream(response, responseBytes, resolver.BlockedIf))
                {
                    response.Blocked = true;
                    response.BlockedBy = resolver.Name;
                    response.BlockedReason = "BlockedUpstream";
                }
                return response;
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Log($"DnsServerTimeout DOH: {query.QueryDomain} using {resolver.Name}");
            throw;
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsServerFail DOH: {query.QueryDomain} using {resolver.Name}: {ex.Message}");
            throw;
        }

        return null;
    }

    public static async Task<DnsResponse?> QueryAsyncDOT(DnsQuery query, Resolver resolver, int timeout, CancellationToken token)
    {
        TcpClient? tcpClient = null;
        SslStream? sslStream = null;

        try
        {
            tcpClient = new TcpClient(resolver.IPAddress.AddressFamily);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);

            await tcpClient.ConnectAsync(resolver.IPAddress, resolver.Port, cts.Token);

            sslStream = new SslStream(tcpClient.GetStream(), false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = resolver.Domain,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            };
            await sslStream.AuthenticateAsClientAsync(options, cts.Token);

            var dnsQuery = DnsQueryBuilder.CreateDOT(
                query.QueryDomain ?? string.Empty,
                query.QueryType
            );

            var length = BitConverter.GetBytes((ushort)dnsQuery.Length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(length);
            await sslStream.WriteAsync(length.Concat(dnsQuery).ToArray(), cts.Token);

            var lengthBuffer = new byte[2];
            await sslStream.ReadExactlyAsync(lengthBuffer, 0, 2, cts.Token);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBuffer);
            int responseLength = BitConverter.ToUInt16(lengthBuffer, 0);

            var responseBuffer = new byte[responseLength];
            await sslStream.ReadExactlyAsync(responseBuffer, 0, responseLength, cts.Token);

            if (responseBuffer.Length > 12)
            {
                var response = DnsResponse.Parse(responseBuffer, query.QueryDomain ?? string.Empty);
                response.ResolvedBy = resolver.Name;
                if (DnsResponse.IsBlockedUpstream(response, responseBuffer, resolver.BlockedIf))
                {
                    response.Blocked = true;
                    response.BlockedBy = resolver.Name;
                    response.BlockedReason = "BlockedUpstream";
                }
                return response;
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Log($"DnsServerTimeout DOT: {query.QueryDomain} using {resolver.Name}");
            throw;
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsServerFail DOT: {query.QueryDomain} using {resolver.Name}: {ex.Message}");
            throw;
        }
        finally
        {
            sslStream?.Dispose();
            tcpClient?.Dispose();
        }

        return null;
    }

    public static async Task<DnsLookup?> QueryAsyncLookup(DnsQuery query, Resolver resolver, int timeout, CancellationToken token)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var udpClient = new UdpClient(AddressFamily.InterNetworkV6);
        udpClient.Client.DualMode = true;

        try
        {
            var endPoint = new IPEndPoint(resolver.IPAddress, resolver.Port);

            var dnsQuery = DnsQueryBuilder.CreateUDP(
                query.QueryDomain ?? string.Empty,
                DnsQueryType.PTR
            );

            await udpClient.SendAsync(dnsQuery, dnsQuery.Length, resolver.IPAddress.ToString(), resolver.Port);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeout);

            var result = await udpClient.ReceiveAsync(cts.Token);
            if (result.Buffer.Length > 12)
            {
                var lookup = DnsLookup.Parse(result.Buffer, query.QueryDomain ?? string.Empty);
                lookup.ResolvedBy = resolver.Name;
                return lookup;
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Log($"DnsServerTimeout Lookup: {query.QueryDomain} using {resolver.Name}");
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsServerFail Lookup: {query.QueryDomain} using {resolver.Name}: {ex.Message}");
        }

        return null;
    }
}
