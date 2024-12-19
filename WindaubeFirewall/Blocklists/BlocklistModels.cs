namespace WindaubeFirewall.Blocklists;

public class OfflineBlocklist
{
    required public string Name { get; set; }
    required public string FilePath { get; set; }
    required public BlockListType Type { get; set; }
    public bool IsEnabled { get; set; } = false;
}

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

public class BlocklistEnabledState
{
    required public string Name { get; set; }
    public bool IsEnabled { get; set; } = false;
}

public class OfflineBlocklistEnabledState
{
    required public string Name { get; set; }
    public bool IsEnabled { get; set; } = false;
}

public enum BlocklistContentType
{
    Domain,
    IP
}

public class Blocklist
{
    required public string Name { get; set; }
    required public BlocklistContentType ContentType { get; set; }
    public BloomFilter Content { get; set; } = null!;
    public int EntryCount { get; set; }
    public bool IsEnabled { get; set; }
}

public enum BlockListType
{
    Wildcard,    // Matches patterns like *.123-proxy.net
    Domain,      // Matches patterns like 123-proxy.net
    Hosts,       // Matches patterns like 0.0.0.0 cdn.0ms.dev
    IP          // Matches patterns like 1.0.0.3
}
