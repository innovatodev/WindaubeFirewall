using System.Runtime.InteropServices;

namespace WindaubeFirewall.Network;

public partial class NetworkTableBase
{
    /// <summary>
    /// Retrieves all IPv4 TCP connections with their associated process IDs
    /// </summary>
    /// <returns>List of TCP IPv4 connections with process information</returns>
    public static List<MIB_TCP4ROW_OWNER_PID> GetExtendedTcp4TableEntries()
    {
        List<MIB_TCP4ROW_OWNER_PID> tcpRows = [];
        int bufferSize = 0;
        nint tcpTablePtr = nint.Zero;

        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            if (result != 0)
            {
                throw new Exception("GetExtendedTcp4Table failed with non-zero return code.");
            }

            uint dwNumEntries = (uint)Marshal.ReadInt32(tcpTablePtr);
            nint rowPtr = nint.Add(tcpTablePtr, Marshal.SizeOf(dwNumEntries));

            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_TCP4ROW_OWNER_PID tcpRow = Marshal.PtrToStructure<MIB_TCP4ROW_OWNER_PID>(rowPtr);
                tcpRows.Add(tcpRow);
                rowPtr = nint.Add(rowPtr, Marshal.SizeOf(typeof(MIB_TCP4ROW_OWNER_PID)));
            }
        }
        finally
        {
            if (tcpTablePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }

        return tcpRows;
    }

    /// <summary>
    /// Retrieves all IPv6 TCP connections with their associated process IDs
    /// </summary>
    /// <returns>List of TCP IPv6 connections with process information</returns>
    public static List<MIB_TCP6ROW_OWNER_PID> GetExtendedTcp6TableEntries()
    {
        List<MIB_TCP6ROW_OWNER_PID> tcpRows = [];
        int bufferSize = 0;
        nint tcpTablePtr = nint.Zero;

        try
        {
            uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 23, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 23, (int)TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            if (result != 0)
            {
                throw new Exception("GetExtendedTcp6Table failed with non-zero return code.");
            }

            uint dwNumEntries = (uint)Marshal.ReadInt32(tcpTablePtr);
            nint rowPtr = nint.Add(tcpTablePtr, Marshal.SizeOf(dwNumEntries));

            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_TCP6ROW_OWNER_PID tcpRow = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                tcpRows.Add(tcpRow);
                rowPtr = nint.Add(rowPtr, Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID)));
            }
        }
        finally
        {
            if (tcpTablePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }

        return tcpRows;
    }

    /// <summary>
    /// Retrieves all IPv4 UDP endpoints with their associated process IDs
    /// </summary>
    /// <returns>List of UDP IPv4 endpoints with process information</returns>
    public static List<MIB_UDP4ROW_OWNER_PID> GetExtendedUdp4TableEntries()
    {
        List<MIB_UDP4ROW_OWNER_PID> udpRows = [];
        int bufferSize = 0;
        nint udpTablePtr = nint.Zero;

        try
        {
            uint result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 2, (int)UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            udpTablePtr = Marshal.AllocHGlobal(bufferSize);
            result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 2, (int)UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

            if (result != 0)
            {
                throw new Exception("GetExtendedUdp4Table failed with non-zero return code.");
            }

            uint dwNumEntries = (uint)Marshal.ReadInt32(udpTablePtr);
            nint rowPtr = nint.Add(udpTablePtr, Marshal.SizeOf(dwNumEntries));

            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_UDP4ROW_OWNER_PID udpRow = Marshal.PtrToStructure<MIB_UDP4ROW_OWNER_PID>(rowPtr);
                udpRows.Add(udpRow);
                rowPtr = nint.Add(rowPtr, Marshal.SizeOf(typeof(MIB_UDP4ROW_OWNER_PID)));
            }
        }
        finally
        {
            if (udpTablePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
        }

        return udpRows;
    }

    /// <summary>
    /// Retrieves all IPv6 UDP endpoints with their associated process IDs
    /// </summary>
    /// <returns>List of UDP IPv6 endpoints with process information</returns>
    public static List<MIB_UDP6ROW_OWNER_PID> GetExtendedUdp6TableEntries()
    {
        List<MIB_UDP6ROW_OWNER_PID> udpRows = [];
        int bufferSize = 0;
        nint udpTablePtr = nint.Zero;

        try
        {
            uint result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 23, (int)UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            udpTablePtr = Marshal.AllocHGlobal(bufferSize);
            result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 23, (int)UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

            if (result != 0)
            {
                throw new Exception("GetExtendedUdp6Table failed with non-zero return code.");
            }

            uint dwNumEntries = (uint)Marshal.ReadInt32(udpTablePtr);
            nint rowPtr = nint.Add(udpTablePtr, Marshal.SizeOf(dwNumEntries));

            for (int i = 0; i < dwNumEntries; i++)
            {
                MIB_UDP6ROW_OWNER_PID udpRow = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                udpRows.Add(udpRow);
                rowPtr = nint.Add(rowPtr, Marshal.SizeOf(typeof(MIB_UDP6ROW_OWNER_PID)));
            }
        }
        finally
        {
            if (udpTablePtr != nint.Zero)
            {
                Marshal.FreeHGlobal(udpTablePtr);
            }
        }

        return udpRows;
    }

    // TCP
    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    // TCP4
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP4ROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP4TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public IntPtr table;
    }

    // TCP6
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public uint remotePort;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public IntPtr table;
    }

    // UDP
    public enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    // UDP4
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP4ROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP4TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public IntPtr table;
    }

    // UDP6
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDP6TABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public IntPtr table;
    }

    // P/Invoke signatures
    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, int ulAf, int TableClass, int Reserved);

    [LibraryImport("iphlpapi.dll", SetLastError = true)]
    private static partial uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, [MarshalAs(UnmanagedType.Bool)] bool bOrder, int ulAf, int TableClass, int Reserved);
}
