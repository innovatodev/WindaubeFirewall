namespace WindaubeFirewall.IPInfos;

/// <summary>
/// Represents IP address information including geolocation and network details
/// from MaxMind GeoLite2 database.
/// </summary>
public class IPInfosModel
{
    /// <summary>Gets or sets the IP address string.</summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>Gets or sets whether the IP is an anycast address.</summary>
    public bool IsAnycast { get; set; } = false;

    /// <summary>Gets or sets the two-letter ISO country code.</summary>
    public string Country { get; set; } = string.Empty;

    /// <summary>Gets or sets the Autonomous System Number.</summary>
    public string ASN { get; set; } = string.Empty;

    /// <summary>Gets or sets the organization name associated with the ASN.</summary>
    public string Organization { get; set; } = string.Empty;

    /// <summary>
    /// Returns a formatted string containing all IP information.
    /// </summary>
    /// <returns>A string representation of the IP data.</returns>
    public override string ToString()
    {
        return $"IPData: {IPAddress} | Anycast: ({IsAnycast}) | ASN: {ASN ?? "N/A"} ORG: {Organization ?? "N/A"} Country: {Country ?? "N/A"}";
    }
}
