using System.Net;
using System.Net.Sockets;

namespace WindaubeFirewall.Utils;

public class IPAddresses
{
    public static bool IsIPV6(IPAddress ipAddress)
    {
        return ipAddress.AddressFamily == AddressFamily.InterNetworkV6;
    }

    public static bool IsPrivateIPv4(IPAddress ipAddress)
    {
        byte[] addressBytes = ipAddress.GetAddressBytes();
        // Class A
        if (addressBytes[0] == 10)
        {
            return true;
        }
        // Class B
        if (addressBytes[0] == 172 && addressBytes[1] >= 16 && addressBytes[1] <= 31)
        {
            return true;
        }
        // Class C
        if (addressBytes[0] == 192 && addressBytes[1] == 168)
        {
            return true;
        }
        return false;
    }

    private static bool IsIPv4LinkLocal(IPAddress ipAddress)
    {
        byte[] addressBytes = ipAddress.GetAddressBytes();
        return addressBytes[0] == 169 && addressBytes[1] == 254;
    }
    public static bool IsBroadcastAddress(IPAddress ipAddress)
    {
        return ipAddress.Equals(IPAddress.Broadcast);
    }

    public static bool IsMulticastAddress(IPAddress ipAddress)
    {
        byte[] addressBytes = ipAddress.GetAddressBytes();
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 Multicast: 224.0.0.0 to 239.255.255.255
            return addressBytes[0] >= 224 && addressBytes[0] <= 239;
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6 Multicast: FF00::/8
            return addressBytes[0] == 0xFF;
        }
        return false;
    }

    private static bool IsLocalMulticast(IPAddress ipAddress)
    {
        byte[] addressBytes = ipAddress.GetAddressBytes();
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 Local Multicast ranges:
            // 224.0.0.0/24: Local Network Control Block
            // 239.0.0.0/8: Administrative Scope
            return (addressBytes[0] == 224 && addressBytes[1] == 0 && addressBytes[2] == 0) ||
                   (addressBytes[0] == 239);
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6 Local Multicast ranges:
            // FF01::/16: Interface-Local
            // FF02::/16: Link-Local
            // FF05::/16: Site-Local
            return addressBytes[0] == 0xFF && (addressBytes[1] == 0x01 || addressBytes[1] == 0x02 || addressBytes[1] == 0x05);
        }
        return false;
    }

    public static int GetIPScope(IPAddress ipAddress)
    {
        if (IPAddress.IsLoopback(ipAddress))
        {
            return 0; // Loopback zone
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            if (IsIPv4LinkLocal(ipAddress) || IsPrivateIPv4(ipAddress))
            {
                return 2; // LAN zone (IPv4 link-local or private)
            }
        }
        else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipAddress.IsIPv6LinkLocal)
            {
                return 2; // LAN zone (IPv6 link-local)
            }
        }

        if (IsMulticastAddress(ipAddress))
        {
            return IsLocalMulticast(ipAddress) ? 1 : 3; // Local multicast (1) or Internet multicast (3)
        }

        return 3; // Internet zone
    }

    private static IPAddress CreateIPv6Mask(int prefixLength)
    {
        if (prefixLength < 0 || prefixLength > 128)
            throw new ArgumentException("IPv6 prefix length must be between 0 and 128");

        var maskBytes = new byte[16];
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        // Fill full bytes with 1s
        for (int i = 0; i < fullBytes; i++)
        {
            maskBytes[i] = 0xFF;
        }

        // Fill remaining bits
        if (fullBytes < 16 && remainingBits > 0)
        {
            maskBytes[fullBytes] = (byte)(0xFF << (8 - remainingBits));
        }

        return new IPAddress(maskBytes);
    }

    public static IPAddress GetNetworkAddress(IPAddress address, IPAddress subnetMask)
    {
        if (address.AddressFamily != subnetMask.AddressFamily)
            throw new ArgumentException("Address and mask must be of the same address family");

        byte[] ipBytes = address.GetAddressBytes();
        byte[] maskBytes = subnetMask.GetAddressBytes();
        byte[] networkBytes = new byte[ipBytes.Length];

        for (int i = 0; i < ipBytes.Length; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
        }

        return new IPAddress(networkBytes);
    }

    public static IPAddress GetNetworkAddress(IPAddress address, int prefixLength)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork && (prefixLength < 0 || prefixLength > 32))
            throw new ArgumentException("IPv4 prefix length must be between 0 and 32");

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && (prefixLength < 0 || prefixLength > 128))
            throw new ArgumentException("IPv6 prefix length must be between 0 and 128");

        IPAddress mask = address.AddressFamily == AddressFamily.InterNetworkV6
            ? CreateIPv6Mask(prefixLength)
            : new IPAddress(new byte[] {
                (byte)(0xFF << (8 - Math.Min(8, prefixLength))),
                (byte)(0xFF << (8 - Math.Max(0, Math.Min(8, prefixLength - 8)))),
                (byte)(0xFF << (8 - Math.Max(0, Math.Min(8, prefixLength - 16)))),
                (byte)(0xFF << (8 - Math.Max(0, Math.Min(8, prefixLength - 24))))
            });

        return GetNetworkAddress(address, mask);
    }

    public static IPAddress GetBroadcastAddress(IPAddress address, IPAddress subnetMask)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 addresses are supported");

        byte[] ipBytes = address.GetAddressBytes();
        byte[] maskBytes = subnetMask.GetAddressBytes();
        byte[] broadcastBytes = new byte[4];

        for (int i = 0; i < 4; i++)
        {
            broadcastBytes[i] = (byte)(ipBytes[i] | (maskBytes[i] ^ 255));
        }

        return new IPAddress(broadcastBytes);
    }

    public static bool IsInSameSubnet(IPAddress address1, IPAddress address2, IPAddress subnetMask)
    {
        if (address1.AddressFamily != address2.AddressFamily ||
            address1.AddressFamily != subnetMask.AddressFamily)
            return false;

        IPAddress network1 = GetNetworkAddress(address1, subnetMask);
        IPAddress network2 = GetNetworkAddress(address2, subnetMask);

        return network1.Equals(network2);
    }

    public static bool IsInSameSubnet(IPAddress address1, IPAddress address2, int prefixLength)
    {
        if (address1.AddressFamily != address2.AddressFamily)
            return false;

        IPAddress network1 = GetNetworkAddress(address1, prefixLength);
        IPAddress network2 = GetNetworkAddress(address2, prefixLength);

        return network1.Equals(network2);
    }
}
