namespace WindaubeFirewall.IPInfos;

public class IPInfosModel
{
    public string IPAddress { get; set; } = string.Empty;
    public bool IsAnycast { get; set; } = false;
    public string Country { get; set; } = string.Empty;
    public string ASN { get; set; } = string.Empty;
    public string Organization { get; set; } = string.Empty;

    public override string ToString()
    {
        return $"IPData: {IPAddress} | Anycast: ({IsAnycast}) | ASN: {ASN ?? "N/A"} ORG: {Organization ?? "N/A"} Country: {Country ?? "N/A"}";
    }
}
