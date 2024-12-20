namespace WindaubeFirewall.Network;

public class NetworkTableWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    private static Thread? _workerThread;

    public const int MAX_CACHE_SIZE = 1024;
    public static DateTime LastUpdate { get; set; } = DateTime.MinValue;

    public static List<NetworkTableTCP4> NetworkTableTcp4Active { get; set; } = [];
    public static List<NetworkTableTCP6> NetworkTableTcp6Active { get; set; } = [];
    public static List<NetworkTableUDP4> NetworkTableUdp4Active { get; set; } = [];
    public static List<NetworkTableUDP6> NetworkTableUdp6Active { get; set; } = [];

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
