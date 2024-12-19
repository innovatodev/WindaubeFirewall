using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

using WindaubeFirewall.Blocklists;

namespace WindaubeFirewall.DnsServer;

public class DnsServerWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    public static bool IsEnabled { get; set; }

    private static SemaphoreSlim _querySemaphore = new(App.SettingsApp.DnsServer.MaxConcurrentQueries);
    private static readonly Lock _lock = new();

    private static Thread? _workerThread;

    private static UdpClient? _dnsServer;
    public static List<Resolver> _resolvers = [];

    private static readonly Dictionary<string, int> _resolverFailures = new();
    private static readonly Dictionary<string, DateTime> _resolverFailureTimes = new();
    private static Timer? _recoveryTimer;

    // Dns cache
    public static readonly ConcurrentDictionary<string, DnsResponse> _dnsCache = new();
    // Dns responses store
    public static readonly ConcurrentDictionary<DateTime, DnsResponse> _dnsResponseStore = new();

    private static readonly ConcurrentDictionary<string, List<IPEndPoint>> _pendingQueryClients = new();
    private static readonly ConcurrentQueue<DnsQuery> _pendingQueries = new();
    private static readonly List<Task> _activeQueries = [];

    public static void DoWork()
    {
        while (!IsCancellationRequested)
        {
            try
            {
                if (!IsEnabled || _dnsServer == null) { continue; }

                lock (_lock)
                {
                    if (_dnsServer == null) continue;

                    if (_dnsServer.Available > 0)
                    {
                        var result = _dnsServer.ReceiveAsync().Result;
                        var query = new DnsQuery(result.Buffer, result.RemoteEndPoint);
                        Logger.Log($"DnsServerQuery: {query}");

                        // Check cache first for exact query match (including transaction ID)
                        if (query.QueryDomain != null && _dnsCache.TryGetValue(query.QueryDomain, out var cachedResponse))
                        {
                            if ((DateTime.Now - cachedResponse.Timestamp).TotalSeconds < cachedResponse.TTL)
                            {
                                // Only send response if not blocked
                                if (!cachedResponse.Blocked)
                                {
                                    Logger.Log($"DnsServerCache: {query}");
                                    SendResponse(query, cachedResponse, App._cancellationTokenSource.Token).Wait();
                                    continue;
                                }
                                Logger.Log($"DnsServerCacheBlocked: {query.QueryDomain}");
                            }
                            else
                            {
                                _dnsCache.TryRemove(query.QueryDomain, out _);
                            }
                        }

                        if (!DnsQuery.IsValidQuery(query))
                        {
                            Logger.Log($"DnsServerError: Invalid query received: {query}");
                            // Instead of returning, just skip this query
                            continue;
                        }

                        // Check if query for this domain is already pending and add
                        if (query.QueryDomain != null)
                        {
                            var clientEndpoint = new IPEndPoint(query.IpAddress, query.Port);
                            if (_pendingQueryClients.ContainsKey(query.QueryDomain))
                            {
                                _pendingQueryClients[query.QueryDomain].Add(clientEndpoint);
                            }
                            else
                            {
                                _pendingQueryClients[query.QueryDomain] = new List<IPEndPoint> { clientEndpoint };
                                _pendingQueries.Enqueue(query);
                            }
                        }

                        // Process pending queries
                        while (_pendingQueries.TryDequeue(out var lquery))
                        {
                            var queryTokenSource = new CancellationTokenSource();
                            var queryToken = queryTokenSource.Token;

                            // Set timeout for individual query
                            queryTokenSource.CancelAfter(TimeSpan.FromMilliseconds(App.SettingsApp.DnsServer.QueryTimeout));

                            try
                            {
                                _querySemaphore.Wait(queryToken); // Synchronous wait to ensure proper ordering
                                var task = ProcessQueryAsync(lquery, queryToken)
                                    .ContinueWith(t =>
                                    {
                                        queryTokenSource.Dispose();
                                        _querySemaphore.Release();

                                        if (t.IsFaulted)
                                        {
                                            Logger.Log($"DnsServerError: Query task faulted - {t.Exception?.Message}");
                                        }
                                    }, TaskScheduler.Default);

                                _activeQueries.Add(task);
                            }
                            catch (OperationCanceledException)
                            {
                                Logger.Log($"DnsServerQueryCancelled while waiting: {lquery.QueryDomain}");
                                _querySemaphore.Release();
                                queryTokenSource.Dispose();
                            }
                            catch (Exception ex)
                            {
                                Logger.Log($"DnsServerError starting query: {ex.Message}");
                                _querySemaphore.Release();
                                queryTokenSource.Dispose();
                            }
                        }

                        // Cleanup completed tasks and log any that failed
                        _activeQueries.RemoveAll(t =>
                        {
                            if (t.IsCompleted && t.IsFaulted)
                            {
                                Logger.Log($"DnsServerError: Removing failed task - {t.Exception?.Message}");
                            }
                            return t.IsCompleted;
                        });
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                TryRestart();
            }
            catch (Exception ex)
            {
                Logger.Log($"DnsServerError in worker: {ex.Message}");
                TryRestart();
            }
            Thread.Sleep(1);
        }
    }

    private static void TryRestart()
    {
        try
        {
            Logger.Log("DnsServerWorker attempting restart...");
            lock (_lock)
            {
                // Close existing server
                _dnsServer?.Close();
                _dnsServer?.Dispose();
                _dnsServer = null;

                // Create new server
                _dnsServer = new UdpClient(AddressFamily.InterNetworkV6);
                _dnsServer.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _dnsServer.Client.DualMode = true;
                _dnsServer.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, 53));

                Logger.Log("DnsServerWorker successfully restarted");
            }
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsServerWorker restart failed: {ex.Message}");
            // Wait before next restart attempt
            Thread.Sleep(1000);
        }
    }

    private static string? CleanDomainName(string? domain)
    {
        if (domain == null) return null;

        // Handle .mshome.net
        if (domain.EndsWith(".mshome.net", StringComparison.OrdinalIgnoreCase))
            return domain[..^11];

        // Handle .in-addr.arpa
        if (domain.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
            return domain[..^13];

        // Handle .ip6.arpa
        if (domain.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
            return domain[..^9];

        return domain;
    }

    private static async Task ProcessQueryAsync(DnsQuery query, CancellationToken token)
    {
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(App.SettingsApp.DnsServer.QueryTimeout));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token, timeoutCts.Token, App._cancellationTokenSource.Token);

            // Check cache first
            if (query.QueryDomain != null && _dnsCache.TryGetValue(query.QueryDomain, out var cachedResponse))
            {
                if ((DateTime.Now - cachedResponse.Timestamp).TotalSeconds < cachedResponse.TTL)
                {
                    // Only send response if not blocked
                    if (!cachedResponse.Blocked)
                    {
                        Logger.Log($"DnsServerCache {query}");
                        await SendResponse(query, cachedResponse, linkedCts.Token);
                        return;
                    }
                    Logger.Log($"DnsServerCacheBlocked: {query.QueryDomain}");
                }
                else
                {
                    _dnsCache.TryRemove(query.QueryDomain, out _);
                }
            }

            // Get enabled blocklists from both online and offline sources
            var onlineBlocklistsDomain = App.SettingsApp.Blocklists.OnlineBlocklists
                .Where(b => b.IsEnabled)
                .Select(b => b.Name);
            var offlineBlocklistsDomain = App.SettingsApp.Blocklists.OfflineBlocklists
                .Where(b => b.IsEnabled)
                .Select(b => b.Name);

            // Combine into single list of enabled blocklist names
            var enabledBlocklistsDomain = onlineBlocklistsDomain.Union(offlineBlocklistsDomain).ToList();

            // Check if domain is part of one blocklist
            string? blockingList = null;
            string? blockingReason = null;
            foreach (var blocklist in App.Blocklists.Where(b => enabledBlocklistsDomain.Contains(b.Name)))
            {
                if (blocklist.ContentType == BlocklistContentType.Domain)
                {
                    var domainToCheck = query.QueryDomain;
                    if (domainToCheck != null)
                    {
                        if (blocklist.Content.MightContain(domainToCheck))
                        {
                            blockingList = blocklist.Name;
                            blockingReason = $"Blocklist {blocklist.Name}";
                            break;
                        }
                    }
                }
            }

            // Try resolvers with CNAME resolution
            var response = await ResolveDomainRecursively(query, linkedCts.Token, isBlocked: blockingList != null);
            if (response != null)
            {
                // Mark response as blocked if it was in a blocklist
                if (blockingList != null)
                {
                    response.Blocked = true;
                    response.BlockedBy = blockingList;
                    response.BlockedReason = blockingReason;
                }

                // Cache successful response
                if (query.QueryDomain != null)
                {
                    _dnsCache[query.QueryDomain] = response;
                    _dnsResponseStore[DateTime.Now] = response;
                }

                // Print
                Logger.Log($"DnsServerResponse: {response}");

                // Only send response if not blocked
                if (!response.Blocked)
                {
                    await SendResponse(query, response, linkedCts.Token);
                }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.Log($"Query cancelled: {query.QueryDomain}");
        }
        catch (Exception ex)
        {
            Logger.Log($"Query processing error: {query.QueryDomain} - {ex.Message}");
            // Don't let processing errors take down the server
            // The error is logged and the query is dropped
        }
        finally
        {
            try
            {
                _querySemaphore.Release();

                // Reply to all clients waiting for this query
                if (_dnsServer != null && query.QueryDomain != null &&
                    _pendingQueryClients.TryRemove(query.QueryDomain, out var clients))
                {
                    if (_dnsCache.TryGetValue(query.QueryDomain, out var cachedResponse))
                    {
                        // Only send responses to waiting clients if not blocked
                        if (!cachedResponse.Blocked)
                        {
                            foreach (var client in clients)
                            {
                                var responsePacket = DnsQueryBuilder.CreateResponse(query.RawQuery, cachedResponse);
                                await _dnsServer.SendAsync(responsePacket, responsePacket.Length, client);
                            }
                        }
                        else
                        {
                            Logger.Log($"DnsServerPendingBlocked: {query.QueryDomain} for {clients.Count} clients");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in query cleanup: {ex.Message}");
                // Prevent cleanup errors from propagating
            }
        }
    }

    private static async Task SendResponse(DnsQuery query, DnsResponse response, CancellationToken token)
    {
        if (_dnsServer == null) return;
        var responsePacket = DnsQueryBuilder.CreateResponse(query.RawQuery, response);
        var clientEndpoint = new IPEndPoint(query.IpAddress, query.Port);
        await _dnsServer.SendAsync(responsePacket, responsePacket.Length, clientEndpoint);
    }

    private static async Task<DnsResponse?> TryResolvers(DnsQuery query, CancellationToken token)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            // Select the resolver once before the retry loop
            var resolver = App.SettingsApp.DnsServer.RandomizedClients
                ? Resolver.SelectResolver(_resolvers, ResolverSelectionStrategy.Random)
                : Resolver.SelectResolver(_resolvers, ResolverSelectionStrategy.First);

            if (resolver == null)
            {
                Logger.Log($"DnsServerNoResolvers: No available resolvers for {query.QueryDomain}");
                return null;
            }

            for (int attempt = 0; attempt < App.SettingsApp.DnsServer.MaxRetries; attempt++)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    using var attemptCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(App.SettingsApp.DnsServer.QueryTimeout));
                    using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token, attemptCts.Token);

                    var response = await (resolver.Protocol switch
                    {
                        ResolverProtocolOptions.DNS => DnsClients.QueryAsyncDNS(query, resolver, App.SettingsApp.DnsServer.QueryTimeout, linkedCts.Token),
                        ResolverProtocolOptions.DOH => DnsClients.QueryAsyncDOH(query, resolver, App.SettingsApp.DnsServer.QueryTimeout, linkedCts.Token),
                        ResolverProtocolOptions.DOT => DnsClients.QueryAsyncDOT(query, resolver, App.SettingsApp.DnsServer.QueryTimeout, linkedCts.Token),
                        _ => throw new NotSupportedException($"Unsupported protocol: {resolver.Protocol}")
                    });

                    if (response != null)
                    {
                        sw.Stop();
                        response.ResolvedIn = (int)sw.ElapsedMilliseconds;
                        response.ResolvedBy = resolver.Name;
                        return response;
                    }
                    else
                    {
                        // If response is null, consider it a failure
                        throw new Exception("Null response received from resolver.");
                    }
                }
                catch (Exception ex)
                {
                    HandleResolverFailure(resolver, query, attempt, ex);
                    if (attempt < App.SettingsApp.DnsServer.MaxRetries - 1)
                    {
                        await Task.Delay(1000, token);
                    }
                }
            }
            return null;
        }
        finally
        {
            if (sw.IsRunning) sw.Stop();
        }
    }

    private static void HandleResolverFailure(Resolver resolver, DnsQuery query, int attempt, Exception ex)
    {
        lock (_lock)
        {
            var resolverKey = resolver.Name;

            if (!_resolverFailures.ContainsKey(resolverKey))
            {
                _resolverFailures[resolverKey] = 0;
            }

            var currentFailures = ++_resolverFailures[resolverKey];

            // Debug logging to track failure counts
            Logger.Log($"DnsServerFailCount: {resolver.Name} ({resolver.Protocol}:{resolver.IPAddress}) " +
                      $"failures={currentFailures}/{App.SettingsApp.DnsServer.MaxRetries} " +
                      $"isFailing={resolver.IsFailing}");

            if (currentFailures > App.SettingsApp.DnsServer.MaxRetries && !resolver.IsFailing)
            {
                Logger.Log($"DnsServerMarkedFailing: {resolver.Name} ({resolver.Protocol}:{resolver.IPAddress})");
                resolver.MarkAsFailing();
                _resolverFailureTimes[resolverKey] = DateTime.Now;
                return;
            }
        }
    }

    private static async Task<DnsResponse?> ResolveDomainRecursively(DnsQuery query, CancellationToken token, HashSet<string>? seenCnames = null, bool isBlocked = false)
    {
        seenCnames ??= [];

        // Try to resolve the domain
        var response = await TryResolvers(query, token);

        // Preserve blocked state from original query
        if (response != null && isBlocked)
        {
            response.Blocked = true;
            response.BlockedBy = "Blocklist";
            response.BlockedReason = "BlockedByList";
        }

        if (response == null) return null;

        // If we got an IP address, return it
        if (response.HasIPAddress) return response;

        // Handle CNAME resolution - continue even if blocked
        if (response.CNAME != null && !seenCnames.Contains(response.CNAME))
        {
            // Prevent CNAME loops
            seenCnames.Add(response.CNAME);

            // Don't exceed reasonable CNAME chain length
            if (seenCnames.Count > 10) return response;

            var cnameQuery = new DnsQuery(query.QueryType, response.CNAME, query.IpAddress, query.Port)
            {
                Recurse = true // Set recursive flag for subsequent queries
            };

            // Pass through the blocked state to maintain consistent resolver usage
            var cnameResponse = await ResolveDomainRecursively(cnameQuery, token, seenCnames, isBlocked);

            if (cnameResponse != null)
            {
                // Preserve blocked status and info while merging responses
                response.IPv4Addresses.AddRange(cnameResponse.IPv4Addresses);
                response.IPv6Addresses.AddRange(cnameResponse.IPv6Addresses);
                response.Blocked = response.Blocked || cnameResponse.Blocked || isBlocked;
                if (cnameResponse.Blocked)
                {
                    response.BlockedBy = cnameResponse.BlockedBy;
                    response.BlockedReason = cnameResponse.BlockedReason;
                }
                return response;
            }
        }

        return response;
    }

    private static void ResolverRecover(object? state)
    {
        var now = DateTime.Now;
        var recoveryThreshold = TimeSpan.FromSeconds(App.SettingsApp.DnsServer.ResolverRecoveryTime);

        foreach (var resolver in _resolvers)
        {
            var resolverKey = resolver.Name;

            if (resolver.IsFailing &&
                _resolverFailureTimes.TryGetValue(resolverKey, out var failureTime) &&
                (now - failureTime) >= recoveryThreshold)
            {
                resolver.RestoreFromFailing();
                _resolverFailures[resolverKey] = 0;
                _resolverFailureTimes.Remove(resolverKey);
                Logger.Log($"DnsServerFailingRecover {resolver.Name}");
            }
        }
    }

    public static void Enable()
    {
        lock (_lock)
        {
            if (IsEnabled) return;
            Logger.Log("DnsServerWorker enabling");
            _resolvers = Resolver.ParseResolvers(App.SettingsApp.DnsServer.Resolvers);

            // Clear failure tracking on enable
            _resolverFailures.Clear();
            _resolverFailureTimes.Clear();

            Logger.Log($"Loaded {_resolvers.Count} resolvers");
            Resolver.PrintAll(_resolvers);

            // Start DNS server
            _dnsServer = new UdpClient(AddressFamily.InterNetworkV6);
            _dnsServer.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _dnsServer.Client.DualMode = true;
            _dnsServer.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, 53));

            if (_workerThread == null)
            {
                _workerThread = new Thread(DoWork)
                {
                    IsBackground = true,
                    Name = "DnsServerWorker"
                };
                _workerThread.Start();
            }

            // Initialize recovery timer
            _recoveryTimer = new Timer(ResolverRecover, null, TimeSpan.Zero, TimeSpan.FromSeconds(1));

            IsEnabled = true;
        }
    }

    public static void Disable()
    {
        lock (_lock)
        {
            if (!IsEnabled) return;
            Logger.Log("DnsServerWorker disabling");
            IsEnabled = false;

            // Cleanup recovery timer
            _recoveryTimer?.Dispose();
            _recoveryTimer = null;

            // Close and dispose UDP client
            _dnsServer?.Close();
            _dnsServer?.Dispose();
            _dnsServer = null;
        }
    }

    public static void Start()
    {
        if (App.SettingsApp.DnsServer.IsEnabled)
        {
            Enable();
        }
    }

    public static void Stop()
    {
        Disable();
    }
}
