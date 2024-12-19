
using System.Net;

namespace WindaubeFirewall.Network;

public class NetworkTableService
{
    public static ulong CheckPID(ulong PID, int ipVersion, byte protocol, IPAddress localIP, int localPort, IPAddress remoteIP, int remotePort)
    {
        ulong owningPid = 0;
        bool match = false;
        if (ipVersion == 4 && protocol == 6) // TCP4
        {
            // Active
            if (NetworkTable.NetworkTableTcp4Active != null)
            {
                foreach (var entry in NetworkTable.NetworkTableTcp4Active)
                {
                    //Logger.Log($"[CheckPID_TCP4] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort} - {entry.RemoteAddr}:{entry.RemotePort}");
                    if (entry.LocalAddr.Equals(localIP) && entry.LocalPort == localPort &&
                        entry.RemoteAddr.Equals(remoteIP) && entry.RemotePort == remotePort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }

            // Cache
            if (!match && NetworkTable.NetworkTableTcp4Cache != null)
            {
                foreach (var entry in NetworkTable.NetworkTableTcp4Cache)
                {
                    //Logger.Log($"[CheckPID_TCP4_Cache] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort} - {entry.RemoteAddr}:{entry.RemotePort}");
                    if (entry.LocalAddr.Equals(localIP) && entry.LocalPort == localPort &&
                        entry.RemoteAddr.Equals(remoteIP) && entry.RemotePort == remotePort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }
        }
        else if (ipVersion == 6 && protocol == 6) // TCP6
        {
            // Active
            if (NetworkTable.NetworkTableTcp6Active != null)
            {
                foreach (var entry in NetworkTable.NetworkTableTcp6Active)
                {
                    //Logger.Log($"[CheckPID_TCP6] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort} - {entry.RemoteAddr}:{entry.RemotePort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.LocalPort == localPort &&
                        (entry.RemoteAddr.Equals(remoteIP) || entry.RemoteAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.RemotePort == remotePort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }

            // Cache
            if (!match && NetworkTable.NetworkTableTcp6Cache != null)
            {
                foreach (var entry in NetworkTable.NetworkTableTcp6Cache)
                {
                    //Logger.Log($"[CheckPID_TCP6_Cache] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort} - {entry.RemoteAddr}:{entry.RemotePort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.LocalPort == localPort &&
                        (entry.RemoteAddr.Equals(remoteIP) || entry.RemoteAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.RemotePort == remotePort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }
        }
        else if (ipVersion == 4 && protocol == 17) // UDP4
        {
            // Active
            if (NetworkTable.NetworkTableUdp4Active != null)
            {
                foreach (var entry in NetworkTable.NetworkTableUdp4Active)
                {
                    //Logger.Log($"[CheckPID_UDP4] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                        entry.LocalPort == localPort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }

            // Cache
            if (!match && NetworkTable.NetworkTableUdp4Cache != null)
            {
                foreach (var entry in NetworkTable.NetworkTableUdp4Cache)
                {
                    //Logger.Log($"[CheckPID_UDP4_Cache] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                        entry.LocalPort == localPort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }
        }
        else if (ipVersion == 6 && protocol == 17) // UDP6
        {
            // Active
            if (NetworkTable.NetworkTableUdp6Active != null)
            {
                foreach (var entry in NetworkTable.NetworkTableUdp6Active)
                {
                    //Logger.Log($"[CheckPID_UDP6] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.LocalPort == localPort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }

            // Cache
            if (!match && NetworkTable.NetworkTableUdp6Cache != null)
            {
                foreach (var entry in NetworkTable.NetworkTableUdp6Cache)
                {
                    //Logger.Log($"[CheckPID_UDP6_Cache] {localIP}:{localPort} - {remoteIP}:{remotePort} >>> {entry.LocalAddr}:{entry.LocalPort}");
                    if ((entry.LocalAddr.Equals(localIP) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                        entry.LocalPort == localPort)
                    {
                        match = true;
                        owningPid = entry.OwningPid;
                        break;
                    }
                }
            }
        }

        if (!match)
        {
            //Logger.Log($"[CheckPID] Error: {PID} | {localIP}:{localPort} - {remoteIP}:{remotePort} {StringConverters.ProtocolToString(protocol)}");
        }
        else
        {
            if (PID == owningPid)
            {
                //Logger.Log($"[CheckPID] Match: {PID} == {owningPid} | {localIP}:{localPort} - {remoteIP}:{remotePort} {StringConverters.ProtocolToString(protocol)} [{owningPid}]");
            }
            else
            {
                Logger.Log($"[CheckPID] New: {PID} != {owningPid} | {localIP}:{localPort} - {remoteIP}:{remotePort} {StringConverters.ProtocolToString(protocol)} [{owningPid}]");
            }
        }
        return owningPid;
    }

    public static void UpdateNetworkTables()
    {
        //Logger.Log("[NetworkTable] Updating...");
        var newTcp4 = NetworkTableBase.GetExtendedTcp4TableEntries().Select(entry => new NetworkTableTCP4
        {
            State = entry.state,
            LocalAddr = new IPAddress(entry.localAddr),
            LocalPort = ConvertPortFromNetworkToHostOrder(entry.localPort),
            RemoteAddr = new IPAddress(entry.remoteAddr),
            RemotePort = ConvertPortFromNetworkToHostOrder(entry.remotePort),
            OwningPid = entry.owningPid
        }).ToList();

        var newTcp6 = NetworkTableBase.GetExtendedTcp6TableEntries().Select(entry => new NetworkTableTCP6
        {
            State = entry.state,
            LocalAddr = new IPAddress(entry.localAddr),
            LocalPort = ConvertPortFromNetworkToHostOrder(entry.localPort),
            RemoteAddr = new IPAddress(entry.remoteAddr),
            RemotePort = ConvertPortFromNetworkToHostOrder(entry.remotePort),
            OwningPid = entry.owningPid
        }).ToList();

        var newUdp4 = NetworkTableBase.GetExtendedUdp4TableEntries().Select(entry => new NetworkTableUDP4
        {
            LocalAddr = new IPAddress(entry.localAddr),
            LocalPort = ConvertPortFromNetworkToHostOrder(entry.localPort),
            OwningPid = entry.owningPid
        }).ToList();

        var newUdp6 = NetworkTableBase.GetExtendedUdp6TableEntries().Select(entry => new NetworkTableUDP6
        {
            LocalAddr = new IPAddress(entry.localAddr),
            LocalPort = ConvertPortFromNetworkToHostOrder(entry.localPort),
            OwningPid = entry.owningPid
        }).ToList();

        if (NetworkTableWorker.NetworkTableTcp4Active != null)
        {
            var removedEntries = NetworkTableWorker.NetworkTableTcp4Active.Where(old => !newTcp4.Any(current =>
                current.LocalAddr.Equals(old.LocalAddr) &&
                current.LocalPort == old.LocalPort &&
                current.RemoteAddr.Equals(old.RemoteAddr) &&
                current.RemotePort == old.RemotePort &&
                current.OwningPid == old.OwningPid));

            NetworkTableWorker.NetworkTableTcp4Cache!.AddRange(removedEntries);
            if (NetworkTableWorker.NetworkTableTcp4Cache.Count > NetworkTableWorker.MAX_CACHE_SIZE)
                NetworkTableWorker.NetworkTableTcp4Cache.RemoveRange(0, NetworkTableWorker.NetworkTableTcp4Cache.Count - NetworkTableWorker.MAX_CACHE_SIZE);
        }

        if (NetworkTableWorker.NetworkTableTcp6Active != null)
        {
            var removedEntries = NetworkTableWorker.NetworkTableTcp6Active.Where(old => !newTcp6.Any(current =>
                current.LocalAddr.Equals(old.LocalAddr) &&
                current.LocalPort == old.LocalPort &&
                current.RemoteAddr.Equals(old.RemoteAddr) &&
                current.RemotePort == old.RemotePort &&
                current.OwningPid == old.OwningPid));

            NetworkTableWorker.NetworkTableTcp6Cache!.AddRange(removedEntries);
            if (NetworkTableWorker.NetworkTableTcp6Cache.Count > NetworkTableWorker.MAX_CACHE_SIZE)
                NetworkTableWorker.NetworkTableTcp6Cache.RemoveRange(0, NetworkTableWorker.NetworkTableTcp6Cache.Count - NetworkTableWorker.MAX_CACHE_SIZE);
        }

        if (NetworkTableWorker.NetworkTableUdp4Active != null)
        {
            var removedEntries = NetworkTableWorker.NetworkTableUdp4Active.Where(old => !newUdp4.Any(current =>
                current.LocalAddr.Equals(old.LocalAddr) &&
                current.LocalPort == old.LocalPort &&
                current.OwningPid == old.OwningPid));

            NetworkTableWorker.NetworkTableUdp4Cache!.AddRange(removedEntries);
            if (NetworkTableWorker.NetworkTableUdp4Cache.Count > NetworkTableWorker.MAX_CACHE_SIZE)
                NetworkTableWorker.NetworkTableUdp4Cache.RemoveRange(0, NetworkTableWorker.NetworkTableUdp4Cache.Count - NetworkTableWorker.MAX_CACHE_SIZE);
        }

        if (NetworkTableWorker.NetworkTableUdp6Active != null)
        {
            var removedEntries = NetworkTableWorker.NetworkTableUdp6Active.Where(old => !newUdp6.Any(current =>
                current.LocalAddr.Equals(old.LocalAddr) &&
                current.LocalPort == old.LocalPort &&
                current.OwningPid == old.OwningPid));

            NetworkTableWorker.NetworkTableUdp6Cache!.AddRange(removedEntries);
            if (NetworkTableWorker.NetworkTableUdp6Cache.Count > NetworkTableWorker.MAX_CACHE_SIZE)
                NetworkTableWorker.NetworkTableUdp6Cache.RemoveRange(0, NetworkTableWorker.NetworkTableUdp6Cache.Count - NetworkTableWorker.MAX_CACHE_SIZE);
        }

        NetworkTableWorker.NetworkTableTcp4Active = newTcp4;
        NetworkTableWorker.NetworkTableTcp6Active = newTcp6;
        NetworkTableWorker.NetworkTableUdp4Active = newUdp4;
        NetworkTableWorker.NetworkTableUdp6Active = newUdp6;

        // Set LastUpdate time for the worker to wait 1 second
        NetworkTableWorker.LastUpdate = DateTime.Now;
    }

    private static ushort ConvertPortFromNetworkToHostOrder(uint port)
    {
        return (ushort)((port & 0xFF00) >> 8 | (port & 0x00FF) << 8);
    }

    public static uint? FindProcessByEndpoint(IPAddress localAddr, ushort localPort, bool isIPv6)
    {
        UpdateNetworkTables();
        if (isIPv6)
        {
            // Check UDP6 active
            if (NetworkTableWorker.NetworkTableUdp6Active != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp6Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }

            // Check UDP6 cache
            if (NetworkTableWorker.NetworkTableUdp6Cache != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp6Cache.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }
        }
        else
        {
            // Check UDP4 active
            if (NetworkTableWorker.NetworkTableUdp4Active != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp4Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }

            // Check UDP4 cache

            if (NetworkTableWorker.NetworkTableUdp4Cache != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp4Cache.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }
        }

        return null;
    }

    public static uint? FindActiveProcessByEndpoint(IPAddress localAddr, ushort localPort, bool isIPv6)
    {
        if (isIPv6)
        {
            // Check TCP6 active
            if (NetworkTableWorker.NetworkTableTcp6Active != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp6Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }

            // Check UDP6 active
            if (NetworkTableWorker.NetworkTableUdp6Active != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp6Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }
        }
        else
        {
            // Check TCP4 active
            if (NetworkTableWorker.NetworkTableTcp4Active != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp4Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }

            // Check UDP4 active
            if (NetworkTableWorker.NetworkTableUdp4Active != null)
            {
                var match = NetworkTableWorker.NetworkTableUdp4Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort);
                if (match != null) return match.OwningPid;
            }
        }

        return null;
    }

    public static uint? FindActiveProcessByEndpoint(IPAddress localAddr, ushort localPort, IPAddress remoteAddr, ushort remotePort, bool isIPv6)
    {
        if (isIPv6)
        {
            // Check TCP6 active
            if (NetworkTableWorker.NetworkTableTcp6Active != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp6Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort &&
                    (entry.RemoteAddr.Equals(remoteAddr) || entry.RemoteAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.RemotePort == remotePort);
                if (match != null) return match.OwningPid;
            }

            // Check TCP6 cache
            if (NetworkTableWorker.NetworkTableTcp6Cache != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp6Cache.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.LocalPort == localPort &&
                    (entry.RemoteAddr.Equals(remoteAddr) || entry.RemoteAddr.Equals(IPAddress.IPv6Any)) &&
                    entry.RemotePort == remotePort);
                if (match != null) return match.OwningPid;
            }
        }
        else
        {
            // Check TCP4 active
            if (NetworkTableWorker.NetworkTableTcp4Active != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp4Active.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort &&
                    (entry.RemoteAddr.Equals(remoteAddr) || entry.RemoteAddr.Equals(IPAddress.Any)) &&
                    entry.RemotePort == remotePort);
                if (match != null) return match.OwningPid;
            }

            // Check TCP4 cache
            if (NetworkTableWorker.NetworkTableTcp4Cache != null)
            {
                var match = NetworkTableWorker.NetworkTableTcp4Cache.FirstOrDefault(entry =>
                    (entry.LocalAddr.Equals(localAddr) || entry.LocalAddr.Equals(IPAddress.Any)) &&
                    entry.LocalPort == localPort &&
                    (entry.RemoteAddr.Equals(remoteAddr) || entry.RemoteAddr.Equals(IPAddress.Any)) &&
                    entry.RemotePort == remotePort);
                if (match != null) return match.OwningPid;
            }
        }

        return null;
    }
}
