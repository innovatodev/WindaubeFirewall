using System.Runtime.InteropServices;

namespace WindaubeFirewall.Driver;

public static class DriverCommands
{
    /// <summary>
    /// Available driver commands
    /// </summary>
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

    /// <summary>
    /// Connection verdict types
    /// </summary>
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

    // Command structures for driver communication
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

    private static readonly byte[] EmptyCommand = new byte[1];

    /// <summary>
    /// Converts a structure to a byte array for driver communication.
    /// </summary>
    /// <param name="structure">Structure to convert</param>
    /// <returns>Byte array representation of the structure</returns>
    public static byte[] StructureToByteArray(object structure)
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
