using System.IO;

namespace WindaubeFirewall.Blocklists;

/// <summary>
/// Represents a locally stored blocklist file.
/// </summary>
public class OfflineBlocklist
{
    required public string Name { get; set; }
    required public BlockListType Type { get; set; }
    public bool IsEnabled { get; set; } = false;
    public string FilePath => Path.Combine(Constants.DirectoryBlocklistsOffline, $"{Path.GetFileNameWithoutExtension(Name)}.txt");

}

/// <summary>
/// Represents a blocklist that is downloaded from a remote URL.
/// </summary>
public class OnlineBlocklist
{
    required public string Name { get; set; }
    required public string Uri { get; set; }
    required public int UpdateInterval { get; set; } // [1, 720]
    required public BlockListType Type { get; set; }
    public bool IsAutoUpdate { get; set; } = true;
    public DateTime LastUpdate { get; set; } = DateTime.MinValue;
    public bool IsEnabled { get; set; } = false;
}

/// <summary>
/// Defines the type of content stored in a blocklist.
/// </summary>
public enum BlocklistContentType
{
    /// <summary>Domain names to be blocked</summary>
    Domain,
    /// <summary>IP addresses to be blocked</summary>
    IP
}

/// <summary>
/// Represents a loaded and active blocklist with its filtering data structure.
/// </summary>
public class Blocklist
{
    required public string Name { get; set; }
    required public BlocklistContentType ContentType { get; set; }
    public BloomFilter Content { get; set; } = null!;
    public int EntryCount { get; set; }
    public bool IsEnabled { get; set; }
}

/// <summary>
/// Defines the format of entries in a blocklist file.
/// </summary>
public enum BlockListType
{
    /// <summary>Matches wildcard patterns like *.example.com</summary>
    Wildcard,
    /// <summary>Matches exact domain names like example.com</summary>
    Domain,
    /// <summary>Matches hosts file format like 0.0.0.0 example.com</summary>
    Hosts,
    /// <summary>Matches IP addresses like 1.2.3.4</summary>
    IP
}
