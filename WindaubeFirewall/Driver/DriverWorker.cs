using System.IO;
using Microsoft.Win32.SafeHandles;
using WindaubeFirewall.Connection;
using WindaubeFirewall.Network;

namespace WindaubeFirewall.Driver;

public class DriverWorker
{
    public static bool IsCancellationRequested => App._cancellationTokenSource.IsCancellationRequested;
    private static Thread? _workerThread;
    private static Thread? _bandwidthThread;

    // Handles
    public static SafeFileHandle? KextFileHandle { get; set; }
    public static FileStream? KextFileStreamReader { get; set; }
    public static BinaryReader? KextBinaryReader { get; set; }
    public static FileStream? KextFileStreamWriter { get; set; }
    public static BinaryWriter? KextBinaryWriter { get; set; }

    private static readonly object WriterLock = new();
    public static object GetWriterLock() => WriterLock;

    /// <summary>
    /// Main worker method that continuously processes information from the driver.
    /// Handles various types of connections and events including IPv4, IPv6, connection ends, and bandwidth statistics.
    /// </summary>
    public static void DoWork()
    {
        while (!IsCancellationRequested)
        {
            var info = DriverInfoReader.ReceiveInfo();
            if (info == null) { continue; }

            if (!IsCancellationRequested)
            {
                if (info.ConnectionV4 != null)
                {
                    NetworkTableService.UpdateNetworkTables();

                    var eventObject = new ConnectionEvent
                    {
                        ID = info.ConnectionV4.ID,
                        ProcessID = info.ConnectionV4.ProcessID,
                        Direction = info.ConnectionV4.Direction,
                        Protocol = info.ConnectionV4.Protocol,
                        LocalIP = info.ConnectionV4.LocalIP,
                        RemoteIP = info.ConnectionV4.RemoteIP,
                        LocalPort = info.ConnectionV4.LocalPort,
                        RemotePort = info.ConnectionV4.RemotePort,
                        PayloadLayer = info.ConnectionV4.PayloadLayer,
                        PayloadSize = info.ConnectionV4.PayloadSize,
                        Payload = info.ConnectionV4.Payload
                    };
                    ConnectionWorker._connectionQueue.TryAdd(DateTime.Now, eventObject);
                    continue;
                }
                if (info.ConnectionV6 != null)
                {
                    NetworkTableService.UpdateNetworkTables();

                    var eventObject = new ConnectionEvent
                    {
                        ID = info.ConnectionV6.ID,
                        ProcessID = info.ConnectionV6.ProcessID,
                        Direction = info.ConnectionV6.Direction,
                        Protocol = info.ConnectionV6.Protocol,
                        LocalIP = info.ConnectionV6.LocalIP,
                        RemoteIP = info.ConnectionV6.RemoteIP,
                        LocalPort = info.ConnectionV6.LocalPort,
                        RemotePort = info.ConnectionV6.RemotePort,
                        PayloadLayer = info.ConnectionV6.PayloadLayer,
                        PayloadSize = info.ConnectionV6.PayloadSize,
                        Payload = info.ConnectionV6.Payload
                    };
                    ConnectionWorker._connectionQueue.TryAdd(DateTime.Now, eventObject);
                    continue;
                }

                if (info.ConnectionEndV4 != null)
                {
                    var endEvent = new ConnectionEndEvent
                    {
                        ProcessID = (int)info.ConnectionEndV4.ProcessID,
                        Direction = info.ConnectionEndV4.Direction,
                        Protocol = info.ConnectionEndV4.Protocol,
                        LocalIP = info.ConnectionEndV4.LocalIP,
                        RemoteIP = info.ConnectionEndV4.RemoteIP,
                        LocalPort = info.ConnectionEndV4.LocalPort,
                        RemotePort = info.ConnectionEndV4.RemotePort
                    };
                    ConnectionWorker._connectionEndQueue.TryAdd(DateTime.Now, endEvent);
                    continue;
                }
                if (info.ConnectionEndV6 != null)
                {
                    var endEvent = new ConnectionEndEvent
                    {
                        ProcessID = (int)info.ConnectionEndV6.ProcessID,
                        Direction = info.ConnectionEndV6.Direction,
                        Protocol = info.ConnectionEndV6.Protocol,
                        LocalIP = info.ConnectionEndV6.LocalIP,
                        RemoteIP = info.ConnectionEndV6.RemoteIP,
                        LocalPort = info.ConnectionEndV6.LocalPort,
                        RemotePort = info.ConnectionEndV6.RemotePort
                    };
                    ConnectionWorker._connectionEndQueue.TryAdd(DateTime.Now, endEvent);
                    continue;
                }

                if (info.BandwidthStats != null)
                {
                    ConnectionWorker._connectionBandwidthQueue.TryAdd(DateTime.Now, info.BandwidthStats);
                }
                //info.ConnectionV4?.Print();
                //info.ConnectionV6?.Print();
                //info.ConnectionEndV4?.Print();
                //info.ConnectionEndV6?.Print();
                //info.BandwidthStats?.Print();
                info.LogLine?.Print();
            }
        }
    }

    /// <summary>
    /// Background worker method that periodically requests bandwidth statistics from the driver.
    /// </summary>
    private static void BandwidthStatsWork()
    {
        while (!IsCancellationRequested)
        {
            lock (WriterLock)
            {
                DriverInfoSender.CommandGetBandwidthStats();
            }
            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Sends a verdict decision for a specific connection to the driver.
    /// </summary>
    /// <param name="verdictID">The unique identifier of the connection</param>
    /// <param name="verdict">The verdict decision to be applied</param>
    public static void SendVerdict(ulong verdictID, DriverCommands.Verdict verdict)
    {
        if (!IsCancellationRequested)
        {
            lock (WriterLock)
            {
                DriverInfoSender.CommandSendVerdict(verdictID, (DriverInfoSender.Commands.Verdict)verdict);
            }
        }
    }

    /// <summary>
    /// Initializes and starts the driver worker threads and establishes necessary driver connections.
    /// </summary>
    public static void Start()
    {
        lock (WriterLock)
        {
            DriverManager.InstallDriver();
            DriverManager.StartDriver();

            // IOCTL
            KextFileHandle = IOCTL.CreateFile(@"\\.\PortmasterKext", 0xC0000000, 0, nint.Zero, 3, 0, nint.Zero);
            if (KextFileHandle is null || KextFileHandle.IsInvalid)
            {
                throw new Exception("Failed to open KextFileHandle.");
            }
            Logger.Log($"Driver Version: {IOCTL.GetVersion(KextFileHandle)}");
            // Handles
            KextFileStreamReader = new FileStream(KextFileHandle, FileAccess.Read);
            KextBinaryReader = new BinaryReader(KextFileStreamReader);
            KextFileStreamWriter = new FileStream(KextFileHandle, FileAccess.Write);
            KextBinaryWriter = new BinaryWriter(KextFileStreamWriter);

            _workerThread = new Thread(DoWork)
            {
                IsBackground = true,
                Name = "DriverWorker"
            };
            _bandwidthThread = new Thread(BandwidthStatsWork)
            {
                IsBackground = true,
                Name = "BandwidthStats"
            };

            _workerThread.Start();
            _bandwidthThread.Start();
        }
    }

    /// <summary>
    /// Stops the driver worker threads and cleans up all driver-related resources.
    /// </summary>
    public static void Stop()
    {
        lock (WriterLock)
        {
            _workerThread?.Join(1000);
            _bandwidthThread?.Join(1000);
            KextBinaryWriter?.Dispose();
            KextBinaryWriter = null;
            KextFileStreamWriter?.Dispose();
            KextFileStreamWriter = null;
            KextBinaryReader?.Dispose();
            KextBinaryReader = null;
            KextFileStreamReader?.Dispose();
            KextFileStreamReader = null;
            KextFileHandle?.Dispose();
            KextFileHandle = null;
            DriverManager.CleanDriver();
        }
    }
}
