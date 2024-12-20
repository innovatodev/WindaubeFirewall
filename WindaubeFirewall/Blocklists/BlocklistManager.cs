using System.IO;
using System.Net.Http;

using WindaubeFirewall.Settings;

namespace WindaubeFirewall.Blocklists;

/// <summary>
/// Manages the loading, updating, and processing of DNS and IP blocklists.
/// Handles both online and offline blocklists, including automatic updates
/// and file parsing for different blocklist formats.
/// </summary>
public class BlocklistManager
{
    public static List<string> LoadDnsBlocklistsDomains()
    {
        try
        {
            if (File.Exists(Constants.BLOCKLIST_DNS_DOMAINS))
            {
                return File.ReadAllLines(Constants.BLOCKLIST_DNS_DOMAINS)
                    .Where(line => !string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith("//"))
                    .ToList();
            }
            else
            {
                Logger.Log($"DNS domains blocklist not found: {Constants.BLOCKLIST_DNS_DOMAINS}");
            }
        }
        catch (Exception ex)
        {
            Logger.Log($"Error loading DNS domains blocklist: {ex.Message}");
        }
        return [];
    }

    public static List<string> LoadDnsBlocklistsIP()
    {
        try
        {
            if (File.Exists(Constants.BLOCKLIST_DNS_IP))
            {
                return File.ReadAllLines(Constants.BLOCKLIST_DNS_IP)
                    .Where(line => !string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith("//"))
                    .ToList();
            }
            else
            {
                Logger.Log($"DNS IP blocklist not found: {Constants.BLOCKLIST_DNS_IP}");
            }

        }
        catch (Exception ex)
        {
            Logger.Log($"Error loading DNS IP blocklist: {ex.Message}");
        }
        return [];
    }

    public static (List<string> Domains, List<string> IpAddresses) LoadDnsBlocklists()
    {
        return (LoadDnsBlocklistsDomains(), LoadDnsBlocklistsIP());
    }

    public static void UpdateOnlineBlocklist(OnlineBlocklist blocklist)
    {
        try
        {
            string filePath = Path.Combine(Constants.DirectoryBlocklistsOnline, $"{blocklist.Name}.txt");
            Directory.CreateDirectory(Constants.DirectoryBlocklistsOnline);
            using var client = new HttpClient();
            var response = client.GetAsync(blocklist.Uri).GetAwaiter().GetResult();
            response.EnsureSuccessStatusCode();

            var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            File.WriteAllText(filePath, content);

            // Set last update time and save
            blocklist.LastUpdate = DateTime.Now;
            SettingsManager.SaveSettingsApplication(App.SettingsApp);

            Logger.Log($"Updated online blocklist: {blocklist.Name}");
        }
        catch (Exception ex)
        {
            Logger.Log($"Error updating online blocklist {blocklist.Name}: {ex.Message}");
            throw;
        }
    }

    public static void UpdateOnlineBlocklists(IEnumerable<OnlineBlocklist> blocklists)
    {
        Directory.CreateDirectory(Constants.DirectoryBlocklistsOnline);

        foreach (var blocklist in blocklists.Where(b => b.IsAutoUpdate))
        {
            if (ShouldUpdate(blocklist))
            {
                UpdateOnlineBlocklist(blocklist);
            }
        }
    }

    private static bool ShouldUpdate(OnlineBlocklist blocklist)
    {
        return blocklist.LastUpdate.AddHours(blocklist.UpdateInterval) < DateTime.Now;
    }

    public static List<Blocklist> LoadBlocklists()
    {
        var blocklists = new List<Blocklist>();

        // Load offline blocklists
        foreach (var offlineList in App.SettingsApp.Blocklists.OfflineBlocklists)
        {
            if (!File.Exists(offlineList.FilePath))
            {
                Logger.Log($"Offline blocklist file not found: {offlineList.FilePath}");
                continue;
            }

            var blocklist = LoadBlocklist(offlineList.Name, offlineList.FilePath, offlineList.Type);
            if (blocklist != null)
            {
                blocklist.IsEnabled = offlineList.IsEnabled;
                blocklists.Add(blocklist);
            }
        }

        // Load online blocklists
        foreach (var onlineList in App.SettingsApp.Blocklists.OnlineBlocklists)
        {
            var filePath = Path.Combine(Constants.DirectoryBlocklistsOnline, $"{onlineList.Name}.txt");
            if (!File.Exists(filePath))
            {
                Logger.Log($"Online blocklist file not found: {filePath}, attempting to update...");
                try
                {
                    UpdateOnlineBlocklist(onlineList);
                }
                catch (Exception ex)
                {
                    Logger.Log($"Failed to update missing blocklist {onlineList.Name}: {ex.Message}");
                    continue;
                }
            }

            var blocklist = LoadBlocklist(onlineList.Name, filePath, onlineList.Type);
            if (blocklist != null)
            {
                blocklist.IsEnabled = onlineList.IsEnabled;
                blocklists.Add(blocklist);
            }
        }

        var ipCount = blocklists.Where(b => b.ContentType == BlocklistContentType.IP)
                           .Sum(b => b.EntryCount);
        var domainCount = blocklists.Where(b => b.ContentType == BlocklistContentType.Domain)
                                .Sum(b => b.EntryCount);

        Logger.Log($"Blocklists: Loaded {blocklists.Count} blocklists | {ipCount} IPs | {domainCount} domains");
        return blocklists;
    }

    /// <summary>
    /// Parses a line from an IP blocklist, handling comments and whitespace.
    /// </summary>
    /// <param name="line">The line to parse</param>
    /// <returns>The parsed IP address or null if line is invalid</returns>
    private static string? ParseIpLine(string line)
    {
        // Split on comment markers and take the first part
        var ipPart = line.Split(new[] { '#', ';' }, 2)[0].Trim();

        // Return null if empty after removing comments
        if (string.IsNullOrWhiteSpace(ipPart))
            return null;

        return ipPart;
    }

    /// <summary>
    /// Loads and initializes a blocklist from a file, creating the appropriate
    /// filtering data structures and validating the content.
    /// </summary>
    /// <param name="name">Name of the blocklist</param>
    /// <param name="filePath">Path to the blocklist file</param>
    /// <param name="type">Type of blocklist entries</param>
    /// <returns>An initialized Blocklist object or null if loading fails</returns>
    public static Blocklist? LoadBlocklist(string name, string filePath, BlockListType type)
    {
        try
        {
            //Logger.Log($"Loading blocklist {name} from {filePath}");
            var content = File.ReadAllLines(filePath)
                .Where(line => !string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith("//") && !line.TrimStart().StartsWith("#"))
                .ToList();

            var contentType = type == BlockListType.IP ? BlocklistContentType.IP : BlocklistContentType.Domain;
            var bloomFilter = new BloomFilter(content.Count, 0.0001); // Set to 0.01% false positive rate
            var exactSet = new HashSet<string>(content.Count); // Store exact matches for validation
            var entryCount = 0;
            var previewEntries = new List<string>();

            foreach (var line in content)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var parsed = type switch
                {
                    BlockListType.IP => ParseIpLine(line),
                    BlockListType.Wildcard => line.TrimStart('*', '.'),
                    BlockListType.Domain => line,
                    BlockListType.Hosts => line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Last(),
                    _ => null
                };

                if (!string.IsNullOrWhiteSpace(parsed))
                {
                    var lowerParsed = parsed.ToLower();
                    bloomFilter.Add(lowerParsed);
                    exactSet.Add(lowerParsed);

                    if (entryCount < 5)
                    {
                        previewEntries.Add(lowerParsed);
                    }
                    entryCount++;
                }
            }

            // Perform false positive testing
            var testSample = exactSet.Take(Math.Min(1000, exactSet.Count)).ToList();
            foreach (var sample in testSample)
            {
                if (!bloomFilter.MightContain(sample))
                {
                    Logger.Log($"Warning: False negative detected in {name} for entry: {sample}");
                }
            }

            var blocklist = new Blocklist
            {
                Name = name,
                ContentType = contentType,
                Content = bloomFilter,
                EntryCount = entryCount
            };

            Logger.Log($"Blocklist: Loaded {name} Type: {contentType} Entries: {entryCount}");
            //Logger.Log($"Blocklist {name} preview entries:");
            foreach (var entry in previewEntries)
            {
                Logger.Log($"  - {entry}");
            }

            return blocklist;
        }
        catch (Exception ex)
        {
            Logger.Log($"Error loading blocklist {name}: {ex.Message}");
            return null;
        }
    }
}
