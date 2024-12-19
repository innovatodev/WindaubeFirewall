using System.IO;

namespace WindaubeFirewall;

public class Constants
{
    // Directories
    public static readonly string DirectoryApplication = AppDomain.CurrentDomain.BaseDirectory;
    public static readonly string DirectoryData = Path.Combine(DirectoryApplication, "Data");
    public static readonly string DirectoryDriverFiles = Path.Combine(DirectoryData, "DriverFiles");
    public static readonly string DirectoryBlocklists = Path.Combine(DirectoryData, "Blocklists");
    public static readonly string DirectoryBlocklistsOnline = Path.Combine(DirectoryBlocklists, "Online");
    public static readonly string DirectoryBlocklistsOffline = Path.Combine(DirectoryBlocklists, "Offline");
    public static readonly string DirectoryBlocklistsBuiltIn = Path.Combine(DirectoryBlocklists, "BuiltIn");
    public static readonly string DirectoryDatabases = Path.Combine(DirectoryData, "Databases");

    public static readonly string DirectoryIPData = Path.Combine(DirectoryData, "IPData");

    // Kext
    public static readonly string KextPath = Path.Combine(DirectoryDriverFiles, "portmaster-kext.sys");
    public static readonly string KextName = "PortmasterKext";

    // Databases
    public static readonly string DatabaseConnection = Path.Combine(DirectoryDatabases, "Connections.db");
    public static readonly string DatabaseConnectionWaitPrompt = Path.Combine(DirectoryDatabases, "ConnectionsWaitPrompt.db");
    public static readonly string DatabaseConnectionWaitResolve = Path.Combine(DirectoryDatabases, "ConnectionsWaitResolve.db");

    // Files
    public static readonly string AppIcon = Path.Combine(DirectoryApplication, "Icon.ico");
    public static readonly string AppSettingsFile = Path.Combine(DirectoryApplication, "AppSettings.yaml");
    public static readonly string AppProfilesFile = Path.Combine(DirectoryApplication, "AppProfiles.yaml");

    // IPData
    public static readonly string IPDataV4 = Path.Combine(DirectoryIPData, "geoipv4.mmdb");
    public static readonly string IPDataV6 = Path.Combine(DirectoryIPData, "geoipv6.mmdb");
    public static readonly string IPDataV4_mini = Path.Combine(DirectoryIPData, "geoipv4-mini.mmdb");
    public static readonly string IPDataV6_mini = Path.Combine(DirectoryIPData, "geoipv6-mini.mmdb");

    // BuiltInBlocklists
    public static readonly string BLOCKLIST_DNS_DOMAINS = Path.Combine(DirectoryBlocklistsBuiltIn, "DNS_DOMAINS.txt");
    public static readonly string BLOCKLIST_DNS_IP = Path.Combine(DirectoryBlocklistsBuiltIn, "DNS_IP.txt");
}
