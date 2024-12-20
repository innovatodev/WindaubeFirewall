using System.ComponentModel;
using YamlDotNet.Serialization;

using WindaubeFirewall.Blocklists;
using WindaubeFirewall.Profiles;
using System.IO;

namespace WindaubeFirewall.Settings;

// Base class for settings with property change notification
public class SettingsBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// Application-level Settings
public class SettingsApplication : SettingsBase
{
    public ApplicationSettings Application { get; set; } = new();
    public DnsServerSettings DnsServer { get; set; } = new();
    public NetworkActionSettings NetworkAction { get; set; } = new()
    {
        DefaultNetworkAction = 1,
        ForceBlockInternet = false,
        ForceBlockLAN = false,
        ForceBlockLocalhost = false,
        ForceBlockIncoming = true,
        BlockBypassDNS = true,
        IncomingRules = [],
        OutgoingRules = []
    };
    public BlocklistsSettingsApplication Blocklists { get; set; } = new();
}

public class ApplicationSettings
{
    public ulong ConnectionEndedTimeout { get; set; } = 600; // [1, 1440]
    public bool ConnectionStoreUseDB { get; set; } = false;
    public bool ProfileGenerateWithEnvVars { get; set; } = true;
}

public class DnsServerSettings
{
    public bool IsEnabled { get; set; } = false; // [True, False]
    public bool RandomizedClients { get; set; } = false; // [True, False]
    public int ResponseStoreTime { get; set; } = 600; // [1, 1440]
    public int MaxConcurrentQueries { get; set; } = 5; // [1, 100]
    public int ResolverRecoveryTime { get; set; } = 10; // [5, 1440]
    public int QueryTimeout { get; set; } = 1000; // [250, 10000]
    public int MaxRetries { get; set; } = 3; // [1, 10]
    public List<string> Resolvers { get; set; } =
    [
        "dns://100.64.0.7?blockedIf=empty&name=MULLVAD1",
        "dns://10.64.0.1?blockedIf=empty&name=MULLVAD2",
        "doh://94.140.14.14?domain=dns.adguard.com&blockedIf=zeroip&name=Adguard1_IPV4",
        "doh://[2a10:50c0::ad1:ff]?domain=dns.adguard.com&blockedIf=zeroip&name=Adguard1_IPV6",
        "dot://94.140.14.14?domain=dns.adguard.com&blockedIf=zeroip&name=Adguard2_IPV4",
        "dot://[2a10:50c0::ad1:ff]?domain=dns.adguard.com&blockedIf=zeroip&name=Adguard2_IPV6",
        "doh://194.242.2.9?domain=all.dns.mullvad.net&blockedIf=empty&name=Mullvad1_IPV4",
        "doh://[2a07:e340::9]?domain=all.dns.mullvad.net&blockedIf=empty&name=Mullvad1_IPV6",
        "dot://194.242.2.9?domain=all.dns.mullvad.net&blockedIf=empty&name=Mullvad2_IPV4",
        "dot://[2a07:e340::9]?domain=all.dns.mullvad.net&blockedIf=empty&name=Mullvad2_IPV6",
        "doh://1.1.1.1?domain=cloudflare-dns.com&blockedIf=zeroip&name=Cloudflare1",
        "dot://1.1.1.1?domain=cloudflare-dns.com&blockedIf=zeroip&name=Cloudflare2",
        "dns://1.1.1.1?blockedIf=zeroip&name=Cloudflare3"
    ];
}

public class NetworkActionSettings
{
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? IsSimpleMode { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public int? DefaultNetworkAction { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? ForceBlockInternet { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? ForceBlockLAN { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? ForceBlockLocalhost { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? ForceBlockIncoming { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? BlockBypassDNS { get; set; } = null;
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public List<string> IncomingRules { get; set; } = new();
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public List<string> OutgoingRules { get; set; } = new();
}

public class BlocklistsSettingsApplication
{
    public List<OfflineBlocklist> OfflineBlocklists { get; set; } =
    [
        new OfflineBlocklist { Name = "DnsBypassOffline", Type = BlockListType.Hosts, IsEnabled = true },
    ];

    public List<OnlineBlocklist> OnlineBlocklists { get; set; } =
        [
        new OnlineBlocklist { Name = "DnsVpnProxy1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass.txt", Type = BlockListType.Wildcard, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsVpnProxy2", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/doh.txt", Type = BlockListType.Hosts, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass2", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh.txt", Type = BlockListType.Wildcard, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass3", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass4", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt", Type = BlockListType.IP, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass5", Uri = "https://raw.githubusercontent.com/jameshas/Public-DoH-Lists/refs/heads/main/lists/doh_ips_plain.txt", Type = BlockListType.IP, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass6", Uri = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt", Type = BlockListType.IP, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "DnsBypass7", Uri = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt", Type = BlockListType.IP, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "ThreatIntelligenceFeeds1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "ThreatIntelligenceFeeds2", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt", Type = BlockListType.IP, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "PopUp1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "Fake1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "MultiPro1", Uri = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true },
        new OnlineBlocklist { Name = "NewlyRegisteredDomains30d1", Uri = "https://raw.githubusercontent.com/xRuffKez/NRD/refs/heads/main/lists/30-day/domains-only/nrd-phishing-30day.txt", Type = BlockListType.Domain, UpdateInterval = 24, IsEnabled = true }
    ];

    public List<OnlineBlocklist> GetEnabledOnlineBlocklists()
    {
        return OnlineBlocklists.Where(bl => bl.IsEnabled).ToList();
    }

    public List<OfflineBlocklist> GetEnabledOfflineBlocklists()
    {
        return OfflineBlocklists.Where(bl => bl.IsEnabled).ToList();
    }
}

// Profile-level Settings
public class SettingsProfiles : SettingsBase
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public List<FingerPrint> Fingerprints { get; set; } = new List<FingerPrint>();
    public bool IsAutoGenerated { get; set; } = false;
    public bool IsSpecial { get; set; } = false;
    public string Icon { get; set; } = string.Empty;

    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public NetworkActionSettings? NetworkAction { get; set; } = null;

    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public BlocklistsSettings? Blocklists { get; set; } = null;
}

public class BlocklistsSettings
{
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public List<OfflineBlocklistEnabledState> OfflineBlocklists { get; set; } = new List<OfflineBlocklistEnabledState>
    {

    };

    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public List<BlocklistEnabledState> OnlineBlocklists { get; set; } = new List<BlocklistEnabledState>
    {

    };
}

public class BlocklistsSettingsProfile
{
    public List<OfflineBlocklistEnabledState> OfflineBlocklists { get; set; } = [];
    public List<BlocklistEnabledState> OnlineBlocklists { get; set; } = [];
}

public class BlocklistEnabledState
{
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    required public string Name { get; set; }

    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? IsEnabled { get; set; } = null;
}

public class OfflineBlocklistEnabledState
{
    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    required public string Name { get; set; }

    [YamlMember(DefaultValuesHandling = DefaultValuesHandling.Preserve)]
    public bool? IsEnabled { get; set; } = null;
}
