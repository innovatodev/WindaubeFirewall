using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;

using WindaubeFirewall.ProcessInfos;
using WindaubeFirewall.Profiles;
using WindaubeFirewall.Settings;

namespace WindaubeFirewall.DnsEventLog;

public class DnsEventLogWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    private static Thread? _workerThread;

    private static TraceEventSession? _dnsSession;
    private static readonly Guid DNS_CLIENT_PROVIDER_GUID = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private static readonly int KEEP_TIME = 600; // seconds

    // Use UID as the key
    public static readonly ConcurrentDictionary<string, DnsQueryEventLog> _dnsEventLogQueries = new();
    public static readonly ConcurrentDictionary<string, DnsResponseEventLog> _dnsEventLogResponses = new();
    private static Task? _cleanupTask;

    // Locks for thread-safe access
    private static readonly ReaderWriterLockSlim _queriesLock = new();
    private static readonly ReaderWriterLockSlim _responsesLock = new();

    // Index for faster IP lookups
    private static readonly ConcurrentDictionary<IPAddress, List<string>> _ipToResponseUids = new();

    public static void DoWork()
    {
        if (_dnsSession?.Source == null) return;

        _dnsSession.Source.Dynamic.All += (TraceEvent ev) =>
        {
            // Get process info
            string processName, processPath, processCommandLine;
            (processName, processPath, processCommandLine) = ProcessInfo.GetProcessInfo(ev.ProcessID);

            if ((int)ev.ID != 3006 && (int)ev.ID != 3008)
                return;

            if ((int)ev.ID == 3006)  // Query
            {
                var queryEvent = new DnsQueryEventLog
                {
                    QueryName = (string)ev.PayloadByName("QueryName"),
                    QueryType = (int)ev.PayloadByName("QueryType"),
                    QueryOptions = (long)ev.PayloadByName("QueryOptions"),
                    ServerList = (string)ev.PayloadByName("ServerList"),
                    IsNetworkQuery = (int)ev.PayloadByName("IsNetworkQuery"),
                    NetworkQueryIndex = (int)ev.PayloadByName("NetworkQueryIndex"),
                    InterfaceIndex = (int)ev.PayloadByName("InterfaceIndex"),
                    IsAsyncQuery = (int)ev.PayloadByName("IsAsyncQuery"),
                    ProcessId = ev.ProcessID,
                    ProcessPath = processPath,
                    ProcessName = processName,
                    ProcessCommandLine = processCommandLine,
                    TimeStamp = DateTime.Now
                };

                // Match processInfo to a profile or generate one
                var matchedProfile = ProfilesManager.MatchProcessInfo(processName, processPath, processCommandLine);
                if (matchedProfile == null)
                {
                    matchedProfile = ProfilesManager.CreateDefaultProfileProcessInfo(processName, processPath, processCommandLine);
                    ProfilesManager.AddProfile(matchedProfile);
                    SettingsManager.SaveSettingsProfiles(App.SettingsProfiles);
                }
                queryEvent.ProfileID = matchedProfile.Id;
                queryEvent.ProfileName = matchedProfile.Name;

                _dnsEventLogQueries.TryAdd($"{queryEvent.QueryName}_{queryEvent.ProcessId}", queryEvent);

                Logger.Log($"DnsEventLogQuery: {queryEvent}");
            }
            else if ((int)ev.ID == 3008) // Response
            {
                var responseEvent = new DnsResponseEventLog
                {
                    QueryName = (string)ev.PayloadByName("QueryName"),
                    QueryType = (int)ev.PayloadByName("QueryType"),
                    QueryOptions = (long)ev.PayloadByName("QueryOptions"),
                    QueryStatus = (int)ev.PayloadByName("QueryStatus"),
                    QueryResults = (string)ev.PayloadByName("QueryResults"),
                    ProcessId = ev.ProcessID,
                    ProcessPath = processPath,
                    ProcessName = processName,
                    ProcessCommandLine = processCommandLine,
                    TimeStamp = DateTime.Now,
                    IpAddresses = [],
                    CNames = []
                };
                // Match processInfo to a profile or generate one
                var matchedProfile = ProfilesManager.MatchProcessInfo(processName, processPath, processCommandLine);
                if (matchedProfile == null)
                {
                    matchedProfile = ProfilesManager.CreateDefaultProfileProcessInfo(processName, processPath, processCommandLine);
                    ProfilesManager.AddProfile(matchedProfile);
                    SettingsManager.SaveSettingsProfiles(App.SettingsProfiles);
                }
                responseEvent.ProfileID = matchedProfile.Id;
                responseEvent.ProfileName = matchedProfile.Name;

                ParseQueryResults(responseEvent);

                // Generate UID from response
                var uid = $"{responseEvent.QueryName}_{responseEvent.ProcessId}";
                _dnsEventLogResponses[uid] = responseEvent;

                Logger.Log($"DnsEventLogResponse: {responseEvent}");
            }
        };

        try
        {
            _dnsSession.Source.Process();
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsEventLogWorker: Error processing events: {ex.Message}");
            throw;
        }

    }

    private static void ParseQueryResults(DnsResponseEventLog response)
    {
        if (string.IsNullOrEmpty(response.QueryResults))
            return;

        var resultArray = response.QueryResults.Split(';', StringSplitOptions.RemoveEmptyEntries);
        foreach (var result in resultArray.AsSpan())
        {
            if (result.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                var dnsValueArray = result.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (dnsValueArray.Length < 3)
                    continue;

                if (int.TryParse(dnsValueArray[1], out int recordType) && recordType == 5)
                {
                    response.CNames[response.QueryName] = dnsValueArray[2];
                }
            }
            else if (IPAddress.TryParse(result.Trim(), out IPAddress? ip))
            {
                response.IpAddresses.Add(ip);

                // Update IP index
                _ipToResponseUids.AddOrUpdate(
                    ip,
                    new List<string> { $"{response.QueryName}_{response.ProcessId}" },
                    (_, list) =>
                    {
                        list.Add($"{response.QueryName}_{response.ProcessId}");
                        return list;
                    });
            }
        }
    }

    private static void CleanupOldRecords()
    {
        var cutoffTime = DateTime.Now.AddSeconds(-KEEP_TIME);

        try
        {
            _queriesLock.EnterWriteLock();
            _responsesLock.EnterWriteLock();

            // Clean queries
            var oldQueries = _dnsEventLogQueries
                .Where(kvp => kvp.Value.TimeStamp < cutoffTime)
                .ToList();

            foreach (var query in oldQueries)
            {
                _dnsEventLogQueries.TryRemove(query.Key, out _);
            }

            // Clean responses and IP index
            var oldResponses = _dnsEventLogResponses
                .Where(kvp => kvp.Value.TimeStamp < cutoffTime)
                .ToList();

            foreach (var response in oldResponses)
            {
                if (_dnsEventLogResponses.TryRemove(response.Key, out var removedResponse))
                {
                    // Clean up IP index
                    foreach (var ip in removedResponse.IpAddresses)
                    {
                        if (_ipToResponseUids.TryGetValue(ip, out var uidList))
                        {
                            uidList.Remove(response.Key);
                            if (uidList.Count == 0)
                            {
                                _ipToResponseUids.TryRemove(ip, out _);
                            }
                        }
                    }
                }
            }
        }
        finally
        {
            _responsesLock.ExitWriteLock();
            _queriesLock.ExitWriteLock();
        }
    }

    public static void Start()
    {
        try
        {
            var existingSession = TraceEventSession.GetActiveSession("UniqueDnsQuerySession");
            existingSession?.Dispose();

            _dnsSession = new TraceEventSession("UniqueDnsQuerySession");
            _dnsSession.EnableProvider(
                DNS_CLIENT_PROVIDER_GUID,
                TraceEventLevel.Verbose,
                0xF0000000000003FF);
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsEventLogWorker: Error: {ex.Message}");
            throw;
        }

        _workerThread = new Thread(DoWork)
        {
            IsBackground = true,
            Name = "DnsEventLog"
        };
        _workerThread.Start();

        // Start cleanup task
        _cleanupTask = Task.Run(async () =>
        {
            while (!IsCancellationRequested)
            {
                CleanupOldRecords();
                await Task.Delay(60000);
            }
        });
    }

    public static void Stop()
    {
        _workerThread?.Join(1000);
        try
        {
            if (_dnsSession != null)
            {
                _dnsSession.Source?.StopProcessing();
                _dnsSession.Dispose();
                _dnsSession = null;
            }

            _queriesLock.Dispose();
            _responsesLock.Dispose();
        }
        catch (Exception ex)
        {
            Logger.Log($"DnsEventLogWorker: Error during disable: {ex.Message}");
        }

    }
}
