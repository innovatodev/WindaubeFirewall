using System.Net.NetworkInformation;
using System.Net.Sockets;
using Windows.Networking.Connectivity;

namespace WindaubeFirewall.Network;

/// <summary>
/// Represents a network adapter with its configuration and status
/// </summary>
public class NetworkAdapter
{
    public string Name { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;
    public OperationalStatus Status { get; set; }
    public string MacAddress { get; set; } = string.Empty;
    public NetworkInterfaceType Type { get; set; }
    public string? IPv4Address { get; set; }
    public string? IPv4Mask { get; set; }
    public string? IPv4Gateway { get; set; }
    public List<string> IPv4DnsServers { get; set; } = [];
    public string? IPv6Address { get; set; }
    public string? IPv6Mask { get; set; }
    public List<string> IPv6DnsServers { get; set; } = [];
    public bool IsDefault { get; set; }

    /// <summary>
    /// Prints detailed information about the network adapter to the log
    /// </summary>
    public void Print()
    {
        Logger.Log($"NetworkAdapter: {Name} ({MacAddress}) {Status}");

        if (IPv4Address != null)
        {
            var dns4 = IPv4DnsServers.Count > 0 ? $" | DNS: {string.Join(", ", IPv4DnsServers)}" : "";
            Logger.Log($"- IPv4: {IPv4Address} | {IPv4Mask} | {IPv4Gateway ?? "No Gateway"}{dns4}");
        }

        if (IPv6Address != null)
        {
            var dns6 = IPv6DnsServers.Count > 0 ? $" | DNS: {string.Join(", ", IPv6DnsServers)}" : "";
            Logger.Log($"- IPv6: {IPv6Address} | {IPv6Mask}{dns6}");
        }
    }
}

/// <summary>
/// Provides methods for managing and monitoring network adapters
/// </summary>
public class NetworkAdapters
{
    /// <summary>
    /// Prints information about all available network adapters
    /// </summary>
    public static void PrintAll()
    {
        var adapters = GetNetworkAdapters();
        foreach (var adapter in adapters)
        {
            adapter.Print();
            Logger.Log("");
        }
    }

    /// <summary>
    /// Gets the ID of the default network adapter used for internet connectivity
    /// </summary>
    /// <returns>The ID of the default adapter, or empty string if not found</returns>
    public static string GetDefaultAdapterID()
    {
        ConnectionProfile? connectionProfile = NetworkInformation.GetInternetConnectionProfile();
        if (connectionProfile?.NetworkAdapter == null) return string.Empty;
        return "{" + connectionProfile.NetworkAdapter.NetworkAdapterId.ToString().ToUpper() + "}";
    }

    /// <summary>
    /// Retrieves a list of all active network adapters with their configurations
    /// </summary>
    /// <returns>List of configured network adapters</returns>
    public static List<NetworkAdapter> GetNetworkAdapters()
    {
        List<NetworkAdapter> networkAdapters = [];
        NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();

        foreach (NetworkInterface adapter in adapters)
        {
            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                adapter.OperationalStatus != OperationalStatus.Up ||
                (adapter.NetworkInterfaceType != NetworkInterfaceType.Ethernet &&
                adapter.NetworkInterfaceType != NetworkInterfaceType.Wireless80211))
            {
                continue;
            }

            var networkAdapter = new NetworkAdapter
            {
                Name = adapter.Name,
                Id = adapter.Id,
                Status = adapter.OperationalStatus,
                MacAddress = BitConverter.ToString(adapter.GetPhysicalAddress().GetAddressBytes()).Replace("-", ""),
                Type = adapter.NetworkInterfaceType
            };

            IPInterfaceProperties adapterProperties = adapter.GetIPProperties();

            foreach (UnicastIPAddressInformation unicastInfo in adapterProperties.UnicastAddresses)
            {
                if (unicastInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    networkAdapter.IPv4Address = unicastInfo.Address.ToString();
                    networkAdapter.IPv4Mask = unicastInfo.IPv4Mask.ToString();
                }
                else if (unicastInfo.Address.AddressFamily == AddressFamily.InterNetworkV6 && unicastInfo.Address.IsIPv6LinkLocal)
                {
                    networkAdapter.IPv6Address = unicastInfo.Address.ToString();
                    networkAdapter.IPv6Mask = unicastInfo.PrefixLength.ToString();
                }
            }

            foreach (GatewayIPAddressInformation gatewayInfo in adapterProperties.GatewayAddresses)
            {
                if (gatewayInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    networkAdapter.IPv4Gateway = gatewayInfo.Address.ToString();
                }
            }

            networkAdapter.IPv4DnsServers = adapterProperties.DnsAddresses
                .Where(addr => addr.AddressFamily == AddressFamily.InterNetwork)
                .Select(addr => addr.ToString())
                .ToList();

            networkAdapter.IPv6DnsServers = adapterProperties.DnsAddresses
                .Where(addr => addr.AddressFamily == AddressFamily.InterNetworkV6)
                .Select(addr => addr.ToString())
                .ToList();

            networkAdapter.IsDefault = adapter.Id == GetDefaultAdapterID();
            if (networkAdapter.IPv4Address != null || networkAdapter.IPv6Address != null)
            {
                networkAdapters.Add(networkAdapter);
            }
        }
        return networkAdapters;
    }

    /// <summary>
    /// Identifies network adapters that have been added since the last check
    /// </summary>
    public static List<NetworkAdapter> GetAddedAdapters(List<NetworkAdapter> current, List<NetworkAdapter> previous)
    {
        return current.Where(c => !previous.Any(p => p.Id == c.Id)).ToList();
    }

    /// <summary>
    /// Identifies network adapters that have been removed since the last check
    /// </summary>
    public static List<NetworkAdapter> GetRemovedAdapters(List<NetworkAdapter> current, List<NetworkAdapter> previous)
    {
        return previous.Where(p => !current.Any(c => c.Id == p.Id)).ToList();
    }
}
