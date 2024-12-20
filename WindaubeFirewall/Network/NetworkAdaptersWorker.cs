namespace WindaubeFirewall.Network;

public class NetworkAdaptersWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    private static Thread? _workerThread;

    public const int MAX_CACHE_SIZE = 1024;
    public static DateTime LastUpdate { get; set; } = DateTime.MinValue;

    /// <summary>
    /// Continuously monitors and updates network adapter information at regular intervals
    /// </summary>
    public static void DoWork()
    {
        while (!IsCancellationRequested)
        {
            // Update network adapters every 60 seconds
            if ((DateTime.Now - LastUpdate).TotalSeconds >= 60)
            {
                App.NetworkAdapters = UpdateNetworkAdapters();
                LastUpdate = DateTime.Now;
            }
            Thread.Sleep(1000);
        }
    }

    /// <summary>
    /// Updates the list of network adapters and logs any changes
    /// </summary>
    /// <returns>Updated list of network adapters</returns>
    public static List<NetworkAdapter> UpdateNetworkAdapters()
    {
        var adapters = NetworkAdapters.GetNetworkAdapters();
        if (App.NetworkAdapters.Count == 0)
        {
            NetworkAdapters.PrintAll();
            return adapters;
        }

        var added = NetworkAdapters.GetAddedAdapters(adapters, App.NetworkAdapters);
        var removed = NetworkAdapters.GetRemovedAdapters(adapters, App.NetworkAdapters);
        var changed = adapters
            .Join(App.NetworkAdapters,
                c => c.Id,
                p => p.Id,
                (c, p) => new { Current = c, Previous = p })
            .Where(x =>
                x.Current.IPv4Address != x.Previous.IPv4Address ||
                x.Current.IPv4Mask != x.Previous.IPv4Mask ||
                x.Current.IPv4Gateway != x.Previous.IPv4Gateway ||
                x.Current.IPv6Address != x.Previous.IPv6Address ||
                x.Current.IPv6Mask != x.Previous.IPv6Mask ||
                !x.Current.IPv4DnsServers.SequenceEqual(x.Previous.IPv4DnsServers) ||
                !x.Current.IPv6DnsServers.SequenceEqual(x.Previous.IPv6DnsServers))
            .Select(x => x.Current)
            .ToList();

        if (added.Count > 0)
        {
            Logger.Log("NetworkAdapter New:");
            added.ForEach(a => a.Print());
        }

        if (removed.Count > 0)
        {
            Logger.Log("NetworkAdapter Removed:");
            removed.ForEach(a => a.Print());
        }

        if (changed.Count > 0)
        {
            Logger.Log("NetworkAdapter Changed:");
            changed.ForEach(a => a.Print());
        }
        return adapters;
    }

    /// <summary>
    /// Initializes and starts the network adapters monitoring thread
    /// </summary>
    public static void Start()
    {
        _workerThread = new Thread(DoWork)
        {
            IsBackground = true,
            Name = "NetworkAdaptersWorker"
        };
        _workerThread.Start();
    }

    /// <summary>
    /// Stops the network adapters monitoring thread
    /// </summary>
    public static void Stop()
    {
        _workerThread?.Join(1000);
    }
}
