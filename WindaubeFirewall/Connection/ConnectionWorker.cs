using System.Collections.Concurrent;
using System.Net.Sockets;

using WindaubeFirewall.Blocklists;
using WindaubeFirewall.Driver;
using WindaubeFirewall.IPInfos;
using WindaubeFirewall.Network;
using WindaubeFirewall.ProcessInfos;
using WindaubeFirewall.Profiles;
using WindaubeFirewall.Settings;

using NetworkActionSettings = WindaubeFirewall.Settings.NetworkActionSettings;

namespace WindaubeFirewall.Connection;

public class ConnectionWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    private static Thread? _processConnectionEventThread;
    private static Thread? _processEndTableThread;
    private static Thread? _processConnectionEndEventThread;
    private static Thread? _processBandwidthEventThread;

    private static readonly IPInfosManager _ipInfosManager = new();
    public static readonly ConcurrentDictionary<DateTime, ConnectionEvent> _connectionQueue = new();
    public static readonly ConcurrentDictionary<DateTime, ConnectionEndEvent> _connectionEndQueue = new();
    public static readonly ConcurrentDictionary<DateTime, DriverInfoReader.DriverInfoBandwidthStats> _connectionBandwidthQueue = new();
    public static readonly ConcurrentDictionary<string, ConnectionModel> _connections = new();
    public static readonly ConcurrentDictionary<string, ConnectionModel> _connectionsDns = new();

    private static void ProcessConnectionEventLoop()
    {
        while (!IsCancellationRequested)
        {
            if (_connectionQueue.Count > 0)
            {
                foreach (var item in _connectionQueue)
                {
                    ProcessConnectionEvent(item.Key, item.Value);
                    _connectionQueue.TryRemove(item.Key, out _);
                }
            }
            Thread.Sleep(1);
        }
    }

    private static void ProcessConnectionEndEventLoop()
    {
        while (!IsCancellationRequested)
        {
            if (_connectionEndQueue.Count > 0)
            {
                foreach (var item in _connectionEndQueue)
                {
                    ProcessConnectionEndEvent(item.Key, item.Value);
                    _connectionEndQueue.TryRemove(item.Key, out _);
                }
            }
            Thread.Sleep(1);
        }
    }

    private static void ProcessBandwidthEventLoop()
    {
        while (!IsCancellationRequested)
        {
            if (_connectionBandwidthQueue.Count > 0)
            {
                foreach (var item in _connectionBandwidthQueue)
                {
                    ProcessBandwidthEvent(item.Value);
                    _connectionBandwidthQueue.TryRemove(item.Key, out _);
                }
            }
            Thread.Sleep(1);
        }
    }

    private static bool GetEffectiveSetting(bool? profileValue, bool? globalValue, bool defaultValue = false)
    {
        return profileValue ?? globalValue ?? defaultValue;
    }

    private static IEnumerable<string> GetEffectiveRules(NetworkActionSettings? profileAction, NetworkActionSettings globalAction, bool incoming)
    {
        var rules = incoming ?
            (profileAction?.IncomingRules ?? globalAction.IncomingRules) :
            (profileAction?.OutgoingRules ?? globalAction.OutgoingRules);
        return rules ?? [];
    }

    private static bool GetEffectiveEnabledState(BlocklistEnabledState? state, bool defaultValue = false)
    {
        return state?.IsEnabled ?? defaultValue;
    }

    private static void ProcessVerdict(ConnectionModel connection)
    {
        // Load profile and app settings
        var profile = App.SettingsProfiles.First(p => p.Id == connection.ProfileID);
        var settings = App.SettingsApp;
        var globalNetworkAction = settings.NetworkAction;

        // Exception for incoming Loopback
        if (connection.Direction == 1 && connection.RemoteScope == 0)
        {
            connection.VerdictString = "ALLOW";
            connection.VerdictReason = "Loopback";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }

        // Check for DNS
        if (connection.IsDNS)
        {
            if (connection.ProfileID == Guid.Parse("00000000-0000-0000-0000-000000000001"))
            {
                connection.VerdictString = "ALLOW";
                connection.VerdictReason = "AllowOwnDNS";
                connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
                DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                Logger.Log($"Connection: {connection}");
                _connectionsDns.TryAdd(connection.ConnectionID, connection);
                return;
            }
            else
            {
                if (App.SettingsApp.DnsServer.IsEnabled == true)
                {
                    connection.VerdictString = "REDIRECT";
                    connection.VerdictReason = "RedirectDNS";
                    connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.RerouteToNameserver;
                    DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                    Logger.Log($"Connection: {connection}");
                    _connectionsDns.TryAdd(connection.ConnectionID, connection);
                    return;
                }
                else
                {
                    var blockBypassDns = GetEffectiveSetting(profile.NetworkAction?.BlockBypassDNS, globalNetworkAction.BlockBypassDNS);
                    if (blockBypassDns)
                    {
                        // Check if it's going to one of the network adapters' DNS servers
                        bool isNetworkAdapterDNS = App.NetworkAdapters.Any(adapter =>
                            adapter.IPv4DnsServers.Contains(connection.RemoteIP.ToString()) ||
                            adapter.IPv6DnsServers.Contains(connection.RemoteIP.ToString()));

                        if (isNetworkAdapterDNS)
                        {
                            connection.VerdictString = "ALLOW";
                            connection.VerdictReason = "AllowNetworkAdapterDNS";
                            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
                        }
                        else
                        {
                            connection.VerdictString = "BLOCK";
                            connection.VerdictReason = "BlockNetworkAdapterDNSBypass";
                            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
                        }
                        DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                        Logger.Log($"Connection: {connection}");
                        _connectionsDns.TryAdd(connection.ConnectionID, connection);
                        return;
                    }
                    else
                    {
                        // Allow any DNS connection
                        connection.VerdictString = "ALLOW";
                        connection.VerdictReason = "AllowExternalDNS";
                        connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
                        DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                        Logger.Log($"Connection: {connection}");
                        _connectionsDns.TryAdd(connection.ConnectionID, connection);
                        return;
                    }

                }
            }
        }

        // Check all force block conditions (highest priority)
        var forceBlockIncoming = GetEffectiveSetting(profile.NetworkAction?.ForceBlockIncoming, globalNetworkAction.ForceBlockIncoming);
        if (forceBlockIncoming && connection.Direction == 1)
        {
            connection.VerdictString = "BLOCK";
            connection.VerdictReason = "ForceBlockIncoming";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }

        var forceBlockLocalhost = GetEffectiveSetting(profile.NetworkAction?.ForceBlockLocalhost, globalNetworkAction.ForceBlockLocalhost);
        if (forceBlockLocalhost && (connection.LocalScope == 0 || connection.RemoteScope == 0))
        {
            connection.VerdictString = "BLOCK";
            connection.VerdictReason = "ForceBlockLocalhost";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }

        var forceBlockLAN = GetEffectiveSetting(profile.NetworkAction?.ForceBlockLAN, globalNetworkAction.ForceBlockLAN);
        if (forceBlockLAN && (connection.LocalScope is 1 or 2 || connection.RemoteScope is 1 or 2))
        {
            connection.VerdictString = "BLOCK";
            connection.VerdictReason = "ForceBlockLAN";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }

        var forceBlockInternet = GetEffectiveSetting(profile.NetworkAction?.ForceBlockInternet, globalNetworkAction.ForceBlockInternet);
        if (forceBlockInternet && (connection.LocalScope == 3 || connection.RemoteScope == 3))
        {
            connection.VerdictString = "BLOCK";
            connection.VerdictReason = "ForceBlockInternet";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }

        // Check BypassDNS
        var BypassDnsEnabled = GetEffectiveSetting(profile.NetworkAction?.BlockBypassDNS, globalNetworkAction.BlockBypassDNS);
        if (BypassDnsEnabled)
        {
            // Check for DNS bypass because IP
            if (App.DnsBlocklistsIP.Contains(connection.RemoteIP.ToString()))
            {
                connection.VerdictString = "BLOCK";
                connection.VerdictReason = "SecureDNSBypass";
                connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
                DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                Logger.Log($"Connection: {connection}");
                _connections.TryAdd(connection.ConnectionID, connection);
                return;
            }
            // Check for DNS bypass because DOT port
            if (connection.RemotePort == 853)
            {
                connection.VerdictString = "BLOCK";
                connection.VerdictReason = "SecureDNSBypassDOT";
                connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
                DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                Logger.Log($"Connection: {connection}");
                _connections.TryAdd(connection.ConnectionID, connection);
                return;
            }
        }

        // Get enabled blocklists from both online and offline sources
        var profileBlocklists = profile.Blocklists?.OnlineBlocklists
            ?.Where(b => GetEffectiveEnabledState(b))
            ?.Select(b => b.Name) ?? Enumerable.Empty<string>();

        var globalBlocklists = settings.Blocklists.OfflineBlocklists
            .Where(b => b.IsEnabled)
            .Select(b => b.Name);

        // Combine into single list of enabled blocklist names
        var enabledBlocklists = profileBlocklists.Union(globalBlocklists).ToList();

        // Check if connection is in any enabled blocklist
        foreach (var blocklist in App.Blocklists.Where(b => enabledBlocklists.Contains(b.Name)))
        {
            if (blocklist.ContentType == BlocklistContentType.IP)
            {
                var ipToCheck = connection.RemoteIP.ToString();
                if (blocklist.Content.MightContain(ipToCheck))
                {
                    connection.VerdictString = "BLOCK";
                    connection.VerdictReason = $"IPBlocklist({blocklist.Name})";
                    connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
                    DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                    Logger.Log($"Connection: {connection}");
                    _connections.TryAdd(connection.ConnectionID, connection);
                    return;
                }
            }
        }

        // Check for rules
        var rules = GetEffectiveRules(profile.NetworkAction, globalNetworkAction, connection.Direction == 1);

        foreach (var ruleString in rules)
        {
            var rule = RuleSet.Parse(ruleString);
            if (rule.Matches(connection))
            {
                if (rule.Action == 0)
                {
                    connection.VerdictString = "BLOCK";
                    connection.VerdictReason = $"Rule({ruleString})";
                    connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
                    DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                    Logger.Log($"Connection: {connection}");
                    _connections.TryAdd(connection.ConnectionID, connection);
                    return;
                }
                else if (rule.Action == 1)
                {
                    connection.VerdictString = "ALLOW";
                    connection.VerdictReason = $"Rule({ruleString})";
                    connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
                    DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                    Logger.Log($"Connection: {connection}");
                    _connections.TryAdd(connection.ConnectionID, connection);
                    return;
                }
                else if (rule.Action == 2)
                {
                    connection.VerdictString = "PROMPT";
                    connection.VerdictReason = $"Rule({ruleString})";
                    connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.Undecided;
                    DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
                    Logger.Log($"Connection: {connection}");
                    _connections.TryAdd(connection.ConnectionID, connection);
                    return;
                }
            }
        }

        // Get default network action
        var defaultNetworkAction = profile.NetworkAction?.DefaultNetworkAction ?? globalNetworkAction.DefaultNetworkAction ?? 1;

        // Check for default network action
        // 0 = block, 1 = allow, 2 = prompt
        if (defaultNetworkAction == 0)
        {
            connection.VerdictString = "BLOCK";
            connection.VerdictReason = "DefaultBlock";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentBlock;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }
        else if (defaultNetworkAction == 1)
        {
            connection.VerdictString = "ALLOW";
            connection.VerdictReason = "DefaultAllow";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.PermanentAccept;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }
        else
        {
            connection.VerdictString = "PROMPT";
            connection.VerdictReason = "DefaultPrompt";
            connection.Verdict = (byte)DriverInfoSender.Commands.Verdict.Undecided;
            DriverWorker.SendVerdict(connection.VerdictID, (DriverCommands.Verdict)connection.Verdict);
            Logger.Log($"Connection: {connection}");
            _connections.TryAdd(connection.ConnectionID, connection);
            return;
        }
    }

    private static void ProcessConnectionEvent(DateTime key, ConnectionEvent Event)
    {
        // ProcessInfo
        var ipVersion = Event.LocalIP.AddressFamily == AddressFamily.InterNetwork ? 4 : 6;
        // CheckPID from NetworkTable
        var checkpid = NetworkTableService.CheckPID(Event.ProcessID, ipVersion, Event.Protocol, Event.LocalIP, Event.LocalPort, Event.RemoteIP, Event.RemotePort);
        ulong usermode_pid = 0;
        // Check if we get a new PID from usermode
        if (Event.ProcessID != checkpid && checkpid != 0)
        {
            usermode_pid = checkpid;
        }

        // Get process info
        string processName, processPath, processCommandLine;
        if (usermode_pid != 0 && Event.ProcessID != checkpid)
        {
            // PID based on user mode
            (processName, processPath, processCommandLine) = ProcessInfo.GetProcessInfo((int)usermode_pid);
        }
        else
        {
            // PID based on driver
            (processName, processPath, processCommandLine) = ProcessInfo.GetProcessInfo((int)Event.ProcessID);
            usermode_pid = Event.ProcessID;
        }

        // DNS Checks
        bool isDNS = false;
        if (Event.Protocol == 17 && Event.RemotePort == 53)
        {
            isDNS = true;
        }

        var localScope = IPAddresses.GetIPScope(Event.LocalIP);
        var remoteScope = IPAddresses.GetIPScope(Event.RemoteIP);

        // Lookup IPInfos only if remote or local scope is Internet (3)
        IPInfosModel? localIPData = null;
        if (remoteScope == 3)
        {
            localIPData = _ipInfosManager.Lookup(Event.RemoteIP.ToString());
        }
        else if (localScope == 3)
        {
            localIPData = _ipInfosManager.Lookup(Event.LocalIP.ToString());
        }

        // Create connection
        var connection = new ConnectionModel
        {
            ProfileID = Guid.Empty,
            ProfileName = string.Empty,
            Verdict = 0,
            VerdictReason = string.Empty,
            VerdictString = string.Empty,
            VerdictID = Event.ID,
            ConnectionID = ConnectionModel.GenerateConnectionID(Event.Protocol, Event.Direction, Event.LocalIP, Event.LocalPort, Event.RemoteIP, Event.RemotePort),
            ProcessID = usermode_pid,
            ProcessIDKext = Event.ProcessID,
            ProcessName = processName,
            ProcessPath = processPath,
            ProcessCommandLine = processCommandLine,
            Direction = Event.Direction,
            Protocol = Event.Protocol,
            LocalScope = localScope,
            RemoteScope = remoteScope,
            IPVersion = ipVersion,
            LocalIP = Event.LocalIP,
            LocalPort = Event.LocalPort,
            RemoteIP = Event.RemoteIP,
            RemotePort = Event.RemotePort,
            StartDate = DateTime.Now,
            SentBytes = 0,
            ReceivedBytes = 0,
            PayloadLayer = Event.PayloadLayer,
            PayloadSize = Event.PayloadSize,
            Payload = Event.Payload,
            IsActive = true,
            IsDNS = isDNS,
            IsAnycast = localIPData?.IsAnycast ?? false,
            Country = localIPData?.Country ?? string.Empty,
            ASN = localIPData?.ASN ?? string.Empty,
            Organization = localIPData?.Organization ?? string.Empty,
        };

        // Match connection to an existing profile
        var matchedProfile = ProfilesManager.MatchConnection(connection);
        if (matchedProfile == null)
        {
            matchedProfile = ProfilesManager.CreateDefaultProfile(connection);
            ProfilesManager.AddProfile(matchedProfile);
            SettingsManager.SaveSettingsProfiles(App.SettingsProfiles);
        }
        connection.ProfileID = matchedProfile.Id;
        connection.ProfileName = matchedProfile.Name;

        ProcessVerdict(connection);
    }

    private static void ProcessConnectionEndEvent(DateTime key, ConnectionEndEvent Event)
    {
        // Generate connection ID for lookup
        string connectionID = ConnectionModel.GenerateConnectionID(Event.Protocol, Event.Direction, Event.LocalIP, Event.LocalPort, Event.RemoteIP, Event.RemotePort);

        // Check active connections
        var connection = GetConnection(connectionID);
        if (connection != null)
        {
            connection.IsActive = false;
            connection.EndDate = DateTime.Now;
        }

        // Check DNS connections
        var connectionDns = GetConnectionDns(connectionID);
        if (connectionDns != null)
        {
            connectionDns.IsActive = false;
            connectionDns.EndDate = DateTime.Now;
        }
    }

    private static void ProcessBandwidthEvent(DriverInfoReader.DriverInfoBandwidthStats Event)
    {
        foreach (var value in Event.Values)
        {
            // Generate connection ID using the same format as connections
            string connectionID = ConnectionModel.GenerateConnectionID(
                Event.Protocol,
                0, // Direction doesn't matter
                value.LocalIP,
                value.LocalPort,
                value.RemoteIP,
                value.RemotePort);

            // Update connection
            var connection = GetConnection(connectionID);
            if (connection != null)
            {
                connection.SentBytes += value.TransmittedBytes;
                connection.ReceivedBytes += value.ReceivedBytes;
                _connections.TryAdd(connection.ConnectionID, connection);
            }

            // Update connection DNS
            var connectionDns = GetConnectionDns(connectionID);
            if (connectionDns != null)
            {
                connectionDns.SentBytes += value.TransmittedBytes;
                connectionDns.ReceivedBytes += value.ReceivedBytes;
                _connectionsDns.TryAdd(connectionDns.ConnectionID, connectionDns);
            }
        }
    }

    private static void ProcessEndTable()
    {
        while (!IsCancellationRequested)
        {
            NetworkTableService.UpdateNetworkTables();

            // Process active connections
            var activeToUpdate = _connections
                .Where(kvp => kvp.Value.IsActive && !IsConnectionActive(kvp.Value))
                .ToList();

            foreach (var item in activeToUpdate)
            {
                item.Value.IsActive = false;
                item.Value.EndDate = DateTime.Now;
                _connections.TryAdd(item.Value.ConnectionID, item.Value);
            }

            // Process DNS connections
            var dnsToUpdate = _connectionsDns
                .Where(kvp => kvp.Value.IsActive && !IsConnectionActive(kvp.Value))
                .ToList();

            foreach (var item in dnsToUpdate)
            {
                item.Value.IsActive = false;
                item.Value.EndDate = DateTime.Now;
                _connectionsDns.TryAdd(item.Value.ConnectionID, item.Value);
            }

            Thread.Sleep(1000);
        }
    }

    private static bool IsConnectionActive(ConnectionModel connection)
    {
        if (connection.Protocol == 6) // TCP
        {
            var pidLocalRemote = NetworkTableService.FindActiveProcessByEndpoint(
                connection.LocalIP,
                connection.LocalPort,
                connection.RemoteIP,
                connection.RemotePort,
                connection.IPVersion == 6);
            var pidRemoteLocal = NetworkTableService.FindActiveProcessByEndpoint(
                connection.RemoteIP,
                connection.RemotePort,
                connection.LocalIP,
                connection.LocalPort,
                connection.IPVersion == 6);
            return pidLocalRemote != null || pidRemoteLocal != null;
        }
        else // UDP
        {
            var pidLocal = NetworkTableService.FindActiveProcessByEndpoint(
                connection.LocalIP,
                connection.LocalPort,
                connection.IPVersion == 6);
            var pidRemote = NetworkTableService.FindActiveProcessByEndpoint(
                connection.RemoteIP,
                connection.RemotePort,
                connection.IPVersion == 6);
            return pidLocal != null || pidRemote != null;
        }
    }

    private static ConnectionModel? GetConnection(string connectionId)
    {
        _connections.TryGetValue(connectionId, out var connection);
        return connection;
    }

    private static ConnectionModel? GetConnectionDns(string connectionId)
    {
        _connectionsDns.TryGetValue(connectionId, out var connection);
        return connection;
    }

    public static void Start()
    {
        // Process Connection Events
        _processConnectionEventThread = new Thread(ProcessConnectionEventLoop)
        {
            IsBackground = true,
            Name = "ProcessConnectionEvent"
        };
        _processConnectionEventThread.Start();

        // Process Connection End Events
        _processConnectionEndEventThread = new Thread(ProcessConnectionEndEventLoop)
        {
            IsBackground = true,
            Name = "ProcessConnectionEndEvent"
        };
        _processConnectionEndEventThread.Start();

        // Process Bandwidth Events
        _processBandwidthEventThread = new Thread(ProcessBandwidthEventLoop)
        {
            IsBackground = true,
            Name = "ProcessBandwidthEvent"
        };
        _processBandwidthEventThread.Start();

        // Process End Table
        _processEndTableThread = new Thread(ProcessEndTable)
        {
            IsBackground = true,
            Name = "ProcessEndTable"
        };

        _processEndTableThread.Start();
    }

    public static void Stop()
    {
        _processConnectionEventThread?.Join(1000);
        _processConnectionEndEventThread?.Join(1000);
        _processBandwidthEventThread?.Join(1000);
        _processEndTableThread?.Join(1000);
    }
}
