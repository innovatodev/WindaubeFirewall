using System.IO;
using System.Net;
using MaxMind.Db;

namespace WindaubeFirewall.IPInfos;

/// <summary>
/// Manages IP information lookups using MaxMind GeoLite2 databases for both IPv4 and IPv6 addresses.
/// </summary>
public class IPInfosManager
{
    // Database readers for IPv4 and IPv6 lookups
    private readonly Reader _readerV4;
    private readonly Reader _readerV6;

    /// <summary>
    /// Initializes a new instance of IPInfosManager, loading both IPv4 and IPv6 databases.
    /// </summary>
    /// <exception cref="FileNotFoundException">Thrown when either database file is not found.</exception>
    public IPInfosManager()
    {
        if (!File.Exists(Constants.IPDataV4))
            throw new FileNotFoundException("IPDataV4 not found", Constants.IPDataV4);
        if (!File.Exists(Constants.IPDataV6))
            throw new FileNotFoundException("IPDataV6 not found", Constants.IPDataV6);

        _readerV4 = new Reader(Constants.IPDataV4);
        _readerV6 = new Reader(Constants.IPDataV6);
    }

    /// <summary>Gets the MaxMind database reader for IPv4 addresses.</summary>
    public Reader ReaderV4 => _readerV4;

    /// <summary>Gets the MaxMind database reader for IPv6 addresses.</summary>
    public Reader ReaderV6 => _readerV6;

    /// <summary>
    /// Looks up information for a given IP address in the appropriate database.
    /// </summary>
    /// <param name="ip">The IP address to look up.</param>
    /// <returns>An IPInfosModel containing the lookup results, or null if lookup fails.</returns>
    public IPInfosModel? Lookup(string ip)
    {
        try
        {
            var ipAddress = IPAddress.Parse(ip);
            // Determine which database to use based on address family
            var isIpv4 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

            // Query the appropriate database
            var record = (isIpv4
                ? _readerV4.Find<Dictionary<string, object?>>(ipAddress)
                : _readerV6.Find<Dictionary<string, object?>>(ipAddress)) ?? new Dictionary<string, object?>();

            // Construct result model
            var info = new IPInfosModel
            {
                IPAddress = ip,
                IsAnycast = record.TryGetValue("is_anycast", out var anycast) && anycast?.ToString() == "True",
                ASN = record.TryGetValue("autonomous_system_number", out var asnValue) ? asnValue?.ToString() ?? string.Empty : string.Empty,
                Organization = record.TryGetValue("autonomous_system_organization", out var orgValue) ? orgValue?.ToString() ?? string.Empty : string.Empty
            };

            // Extract country information from nested dictionary
            if (record.TryGetValue("country", out var countryObj) &&
                countryObj is Dictionary<string, object?> countryData)
            {
                info.Country = countryData.TryGetValue("iso_code", out var isoCode) ? isoCode?.ToString() ?? string.Empty : string.Empty;
            }

            return info;
        }
        catch (Exception ex)
        {
            Logger.Log($"Error looking up IP {ip}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Debug method to print all available properties for a given IP address.
    /// </summary>
    /// <param name="ip">The IP address to test. Defaults to Google's DNS (8.8.8.8).</param>
    public void TestAllProperties(string ip = "8.8.8.8")
    {
        try
        {
            var ipAddress = IPAddress.Parse(ip);
            var isIpv4 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

            // Query database for all available data
            var record = (isIpv4
                ? _readerV4.Find<Dictionary<string, object?>>(ipAddress)
                : _readerV6.Find<Dictionary<string, object?>>(ipAddress));

            if (record == null)
            {
                Logger.Log($"No data found for IP: {ip}");
                return;
            }

            Logger.Log($"\nAll properties for IP {ip}:");
            Logger.Log("----------------------------------------");

            foreach (var kvp in record)
            {
                if (kvp.Value is Dictionary<string, object?> nestedDict)
                {
                    Logger.Log($"{kvp.Key}:");
                    foreach (var nested in nestedDict)
                    {
                        Logger.Log($"  - {nested.Key}: {nested.Value}");
                    }
                }
                else
                {
                    Logger.Log($"{kvp.Key}: {kvp.Value}");
                }
            }
            Logger.Log("----------------------------------------");
        }
        catch (Exception ex)
        {
            Logger.Log($"Error in TestAllProperties for IP {ip}: {ex.Message}");
        }
    }
}
