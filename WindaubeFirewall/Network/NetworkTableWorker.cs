namespace WindaubeFirewall.Network;

/// <summary>
/// Manages network table data updates in a background thread
/// </summary>
public class NetworkTableWorker
{
    /// <summary>
    /// Gets whether the worker has been requested to stop
    /// </summary>
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;

    /// <summary>
    /// Background thread for network table updates
    /// </summary>
    private static Thread? _workerThread;

    /// <summary>
    /// Maximum number of entries to keep in connection caches
    /// </summary>
    public const int MAX_CACHE_SIZE = 1024;

    /// <summary>
    /// Timestamp of last network table update
    /// </summary>
    public static DateTime LastUpdate { get; set; } = DateTime.MinValue;

    // Active connection tables
    public static List<NetworkTableTCP4> NetworkTableTcp4Active { get; set; } = [];
    public static List<NetworkTableTCP6> NetworkTableTcp6Active { get; set; } = [];
    public static List<NetworkTableUDP4> NetworkTableUdp4Active { get; set; } = [];
    public static List<NetworkTableUDP6> NetworkTableUdp6Active { get; set; } = [];

    // Connection caches
    public static List<NetworkTableTCP4> NetworkTableTcp4Cache { get; set; } = [];
    public static List<NetworkTableTCP6> NetworkTableTcp6Cache { get; set; } = [];
    public static List<NetworkTableUDP4> NetworkTableUdp4Cache { get; set; } = [];
    public static List<NetworkTableUDP6> NetworkTableUdp6Cache { get; set; } = [];

    /// <summary>
    /// Continuously monitors and updates network table data at regular intervals
    /// </summary>
    public static void DoWork()
    {
        while (!IsCancellationRequested)
        {
            if ((DateTime.Now - LastUpdate).TotalSeconds >= 1)
            {
                NetworkTableService.UpdateNetworkTables();
                LastUpdate = DateTime.Now;
            }
            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Initializes and starts the network table worker thread
    /// </summary>
    public static void Start()
    {
        _workerThread = new Thread(DoWork)
        {
            IsBackground = true,
            Name = "NetworkTableWorker"
        };

        _workerThread.Start();
    }

    /// <summary>
    /// Stops the network table worker thread
    /// </summary>
    public static void Stop()
    {
        _workerThread?.Join(1000);
    }
}
