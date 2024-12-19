using System.IO;
using System.Net;
using MaxMind.Db;

namespace WindaubeFirewall.IPInfos;

public class IPInfosManager
{
    private readonly Reader _readerV4;
    private readonly Reader _readerV6;

    public IPInfosManager()
    {
        if (!File.Exists(Constants.IPDataV4))
            throw new FileNotFoundException("IPDataV4 not found", Constants.IPDataV4);
        if (!File.Exists(Constants.IPDataV6))
            throw new FileNotFoundException("IPDataV6 not found", Constants.IPDataV6);

        _readerV4 = new Reader(Constants.IPDataV4);
        _readerV6 = new Reader(Constants.IPDataV6);
    }

    public Reader ReaderV4 => _readerV4;
    public Reader ReaderV6 => _readerV6;

    public IPInfosModel? Lookup(string ip)
    {
        try
        {
            var ipAddress = IPAddress.Parse(ip);
            var isIpv4 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            var record = (isIpv4
                ? _readerV4.Find<Dictionary<string, object?>>(ipAddress)
                : _readerV6.Find<Dictionary<string, object?>>(ipAddress)) ?? new Dictionary<string, object?>();

            var info = new IPInfosModel
            {
                IPAddress = ip,
                IsAnycast = record.TryGetValue("is_anycast", out var anycast) && anycast?.ToString() == "True",
                ASN = record.TryGetValue("autonomous_system_number", out var asnValue) ? asnValue?.ToString() ?? string.Empty : string.Empty,
                Organization = record.TryGetValue("autonomous_system_organization", out var orgValue) ? orgValue?.ToString() ?? string.Empty : string.Empty
            };

            if (record.TryGetValue("country", out var countryObj) &&
                countryObj is Dictionary<string, object?> countryData)
            {
                info.Country = countryData.TryGetValue("iso_code", out var isoCode) ? isoCode?.ToString() ?? string.Empty : string.Empty;
            }
            //Logger.Log($"IPDataLookup: {info}");
            return info;
        }
        catch (Exception ex)
        {
            Logger.Log($"Error looking up IP {ip}: {ex.Message}");
            return null;
        }
    }

    public void TestAllProperties(string ip = "8.8.8.8")
    {
        try
        {
            var ipAddress = IPAddress.Parse(ip);
            var isIpv4 = ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
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
