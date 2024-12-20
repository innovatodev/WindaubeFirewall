using System.Net;

namespace WindaubeFirewall.DnsServer;

/// <summary>
/// Represents a DNS resolver with its configuration and current state.
/// Supports multiple resolver protocols (DNS, DOH, DOT) and handles resolver health tracking.
/// </summary>
public class Resolver : IEquatable<Resolver>
{
    /// <summary>
    /// Gets or sets the protocol used by this resolver (DNS, DOH, DOT)
    /// </summary>
    required public ResolverProtocolOptions Protocol { get; set; }
    required public IPAddress IPAddress { get; set; }
    required public ushort Port { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public ResolverBlockedIfOptions BlockedIf { get; set; }
    public bool IsFailing { get; set; } = false;
    public DateTime? FailingSince { get; set; } = null;
    public bool IsBlockedUpstream { get; set; }

    public void MarkAsFailing()
    {
        if (!IsFailing)
        {
            IsFailing = true;
            FailingSince = DateTime.Now;
        }
    }

    public void RestoreFromFailing()
    {
        IsFailing = false;
        FailingSince = null;
    }

    public void MarkAsBlockedUpstream()
    {
        IsBlockedUpstream = true;
    }

    public static Resolver? SelectResolver(List<Resolver> resolvers, ResolverSelectionStrategy strategy)
    {
        var availableResolvers = resolvers.Where(r => !r.IsFailing).ToList();

        if (availableResolvers.Count == 0)
            return null;

        return strategy switch
        {
            ResolverSelectionStrategy.First => availableResolvers.First(),
            ResolverSelectionStrategy.Random => availableResolvers[Random.Shared.Next(availableResolvers.Count)],
            _ => null
        };
    }

    /// <summary>
    /// Parses a list of resolver strings into Resolver objects.
    /// </summary>
    /// <param name="resolverStrings">List of resolver configuration strings</param>
    /// <returns>List of configured resolvers</returns>
    public static List<Resolver> ParseResolvers(List<string> resolverStrings)
    {
        var resolvers = new List<Resolver>();
        foreach (var resolverString in resolverStrings)
        {
            try
            {
                var resolver = ParseResolver(resolverString);
                if (resolver != null)
                {
                    resolvers.Add(resolver);
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Failed to parse resolver: {resolverString}, Error: {ex.Message}");
            }
        }
        return resolvers;
    }

    private static Resolver? ParseResolver(string resolverString)
    {
        var uri = new Uri(resolverString);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);

        var protocol = uri.Scheme.ToUpper() switch
        {
            "DNS" => ResolverProtocolOptions.DNS,
            "DOH" => ResolverProtocolOptions.DOH,
            "DOT" => ResolverProtocolOptions.DOT,
            _ => throw new ArgumentException($"Invalid protocol: {uri.Scheme}")
        };

        // Get port from URI or use default based on protocol
        var port = uri.Port != -1 ? (ushort)uri.Port : protocol switch
        {
            ResolverProtocolOptions.DNS => (ushort)53,
            ResolverProtocolOptions.DOH => (ushort)443,
            ResolverProtocolOptions.DOT => (ushort)853,
            _ => throw new ArgumentException($"No default port for protocol: {protocol}")
        };

        var name = query["name"] ?? query["domain"] ?? uri.Host;
        var domain = query["domain"] ?? string.Empty;

        var blockedIf = query["blockedIf"]?.ToLower() switch
        {
            "refused" => ResolverBlockedIfOptions.Refused,
            "zeroip" => ResolverBlockedIfOptions.ZeroIP,
            "empty" => ResolverBlockedIfOptions.Empty,
            "disabled" => ResolverBlockedIfOptions.Disabled,
            _ => ResolverBlockedIfOptions.Disabled
        };

        var ipAddress = IPAddress.Parse(uri.Host);

        var resolver = new Resolver
        {
            Protocol = protocol,
            IPAddress = ipAddress,
            Port = port,
            Domain = domain,
            BlockedIf = blockedIf,
            Name = name
        };
        return resolver;
    }

    public static string ResolverToString(Resolver resolver)
    {
        if (resolver.Domain == string.Empty)
        {
            return $"{resolver.Name} - {resolver.IPAddress}:{resolver.Port} - {resolver.BlockedIf}";
        }
        else
        {
            return $"{resolver.Name} - {resolver.IPAddress}:{resolver.Port} - {resolver.BlockedIf} - {resolver.Domain}";
        }
    }

    public static void PrintAll(List<Resolver> resolvers)
    {
        foreach (var resolver in resolvers)
        {
            if (resolver.Domain == string.Empty)
            {
                Logger.Log($"{resolver.Name} - {resolver.IPAddress}:{resolver.Port} - {resolver.BlockedIf}");
            }
            else
            {
                Logger.Log($"{resolver.Name} - {resolver.IPAddress}:{resolver.Port} - {resolver.BlockedIf} - {resolver.Domain}");
            }
        }
    }

    public bool Equals(Resolver? other)
    {
        if (other is null)
            return false;

        // Use only immutable properties that uniquely identify the resolver
        return Protocol == other.Protocol &&
               IPAddress.Equals(other.IPAddress) &&
               Port == other.Port;
    }

    public override bool Equals(object? obj) => Equals(obj as Resolver);

    public override int GetHashCode()
    {
        // Use only immutable properties
        return HashCode.Combine(Protocol, IPAddress, Port);
    }
}

/// <summary>
/// Defines detection methods for blocked DNS responses from upstream resolvers.
/// </summary>
public enum ResolverBlockedIfOptions
{
    /// <summary>When resolver returns REFUSED response code</summary>
    Refused,
    /// <summary>When resolver returns 0.0.0.0 or :: addresses</summary>
    ZeroIP,
    /// <summary>When resolver returns empty response</summary>
    Empty,
    /// <summary>Never detect blocked responses</summary>
    Disabled
}

public enum ResolverProtocolOptions
{
    DNS,
    DOH,
    DOT
}

public enum ResolverSelectionStrategy
{
    First,
    Random
}
