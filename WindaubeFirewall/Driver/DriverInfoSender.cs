using System.Runtime.InteropServices;

namespace WindaubeFirewall.Driver;

public class DriverInfoSender
{
    /// <summary>
    /// Validates if the writer is available and ready for writing.
    /// </summary>
    /// <returns>True if writer is valid and ready, false otherwise</returns>
    private static bool ValidateWriter()
    {
        if (DriverWorker.IsCancellationRequested)
        {
            return false;
        }

        try
        {
            if (DriverWorker.KextFileHandle?.IsClosed ?? true)
            {
                return false;
            }
            if (DriverWorker.KextBinaryWriter is null)
            {
                return false;
            }
            if (DriverWorker.KextFileStreamWriter?.CanWrite == false)
            {
                return false;
            }
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Sends a simple command byte to the driver.
    /// </summary>
    /// <param name="command">Command byte to send</param>
    private static void SendCommand(byte command)
    {
        if (DriverWorker.IsCancellationRequested)
        {
            return;
        }

        lock (DriverWorker.GetWriterLock())
        {
            if (ValidateWriter())
            {
                DriverWorker.KextBinaryWriter!.Write(command);
                DriverWorker.KextBinaryWriter.Flush();
            }
        }
    }

    /// <summary>
    /// Sends a structured command to the driver.
    /// </summary>
    /// <typeparam name="T">Structure type that represents the command</typeparam>
    /// <param name="structure">Command structure to send</param>
    private static void SendCommand<T>(T structure) where T : struct
    {
        if (DriverWorker.IsCancellationRequested)
        {
            return;
        }

        lock (DriverWorker.GetWriterLock())
        {
            ValidateWriter();
            try
            {
                DriverWorker.KextBinaryWriter!.Write(StructureToByteArray(structure));
                DriverWorker.KextBinaryWriter.Flush();
            }
            catch (Exception)
            {
                Logger.Log("Failed to send command");
            }

        }
    }

    /// <summary>
    /// Sends a verdict decision for a specific connection.
    /// </summary>
    public static void CommandSendVerdict(ulong id, Commands.Verdict decision)
    {
        //Logger.Log($"SendVerdict: ID={id}, Decision={decision}");
        SendCommand(new Commands.VerdictStruct
        {
            Command = (byte)Commands.Command.Verdict,
            ID = id,
            Decision = (byte)decision
        });
    }

    /// <summary>
    /// Updates IPv4 connection rules in the driver.
    /// </summary>
    public static void SendUpdateV4(byte protocol, byte[] localAddr, ushort localPort, byte[] remoteAddr, ushort remotePort, Commands.Verdict decision)
    {
        Logger.Log($"SendUpdateV4: Protocol={protocol}, LocalAddr={localAddr}, LocalPort={localAddr}, RemoteAddr={remoteAddr}, RemotePort={remotePort}, Decision={decision}");
        SendCommand(new Commands.UpdateV4Struct
        {
            Command = (byte)Commands.Command.UpdateV4,
            Protocol = protocol,
            LocalAddress = localAddr,
            LocalPort = localPort,
            RemoteAddress = remoteAddr,
            RemotePort = remotePort,
            Decision = (byte)decision
        });
    }

    /// <summary>
    /// Updates IPv6 connection rules in the driver.
    /// </summary>
    public static void SendUpdateV6(byte protocol, byte[] localAddr, ushort localPort, byte[] remoteAddr, ushort remotePort, Commands.Verdict decision)
    {
        Logger.Log($"SendUpdateV6: Protocol={protocol}, LocalAddr={localAddr}, LocalPort={localPort}, RemoteAddr={remoteAddr}, RemotePort={remotePort}, Decision={decision}");
        SendCommand(new Commands.UpdateV6Struct
        {
            Command = (byte)Commands.Command.UpdateV6,
            Protocol = protocol,
            LocalAddress = localAddr,
            LocalPort = localPort,
            RemoteAddress = remoteAddr,
            RemotePort = remotePort,
            Decision = (byte)decision
        });
    }

    // Helper command methods
    public static void SendShutdown() => SendCommand((byte)Commands.Command.Shutdown);
    public static void CommandClearCache() => SendCommand((byte)Commands.Command.ClearCache);
    public static void CommandGetLogs() => SendCommand((byte)Commands.Command.GetLogs);
    public static void CommandGetBandwidthStats() => SendCommand((byte)Commands.Command.BandwidthStats);
    public static void CommandPrintMemoryStats() => SendCommand((byte)Commands.Command.PrintMemoryStats);
    public static void CommandCleanEndedConnections() => SendCommand((byte)Commands.Command.CleanEndedConnections);

    public class Commands
    {
        public enum Command : byte
        {
            Shutdown = 0,
            Verdict = 1,
            UpdateV4 = 2,
            UpdateV6 = 3,
            ClearCache = 4,
            GetLogs = 5,
            BandwidthStats = 6,
            PrintMemoryStats = 7,
            CleanEndedConnections = 8
        }

        public enum Verdict : byte
        {
            Undecided = 0,
            Undeterminable = 1,
            Accept = 2,
            PermanentAccept = 3,
            Block = 4,
            PermanentBlock = 5,
            Drop = 6,
            PermanentDrop = 7,
            RerouteToNameserver = 8,
            RerouteToTunnel = 9,
            Failed = 10
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct VerdictStruct
        {
            public byte Command;
            public ulong ID;
            public byte Decision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct UpdateV4Struct
        {
            public byte Command;
            public byte Protocol;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LocalAddress;
            public ushort LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] RemoteAddress;
            public ushort RemotePort;
            public byte Decision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct UpdateV6Struct
        {
            public byte Command;
            public byte Protocol;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] LocalAddress;
            public ushort LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] RemoteAddress;
            public ushort RemotePort;
            public byte Decision;
        }
    }

    private static byte[] StructureToByteArray(object structure)
    {
        int size = Marshal.SizeOf(structure);
        byte[] arr = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);

        Marshal.StructureToPtr(structure, ptr, true);
        Marshal.Copy(ptr, arr, 0, size);
        Marshal.FreeHGlobal(ptr);

        return arr;
    }
}
