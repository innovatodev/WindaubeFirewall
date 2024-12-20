using System.Text.Json.Serialization;

using WindaubeFirewall.Connection;

namespace WindaubeFirewall.Profiles;

/// <summary>
/// Represents a pattern for matching process properties to identify applications
/// </summary>
public class FingerPrint : IEquatable<FingerPrint>
{
    /// <summary>
    /// The type of process property to match against
    /// </summary>
    public FingerprintType Type { get; set; }

    /// <summary>
    /// The comparison operator to use for matching
    /// </summary>
    public MatchOperator Operator { get; set; }

    /// <summary>
    /// The value to match against
    /// </summary>
    public string Value { get; set; } = string.Empty;

    public bool Matches(ConnectionModel connection)
    {
        var valueToMatch = Type switch
        {
            FingerprintType.FullPath => connection.ProcessPath,
            FingerprintType.ProcessName => connection.ProcessName,
            FingerprintType.CommandLine => connection.ProcessCommandLine,
            FingerprintType.WindowsService => connection.ProcessName.StartsWith("SVC:") ?
                connection.ProcessName[4..] : string.Empty,
            FingerprintType.WindowsStore => connection.ProcessName.StartsWith("WinStore:") ?
                connection.ProcessName[9..] : string.Empty,
            _ => string.Empty
        };

        return Operator switch
        {
            MatchOperator.Equals => valueToMatch.Equals(Value, StringComparison.OrdinalIgnoreCase),
            MatchOperator.StartsWith => valueToMatch.StartsWith(Value, StringComparison.OrdinalIgnoreCase),
            MatchOperator.Contains => valueToMatch.Contains(Value, StringComparison.OrdinalIgnoreCase),
            MatchOperator.Wildcard => MatchWildcard(valueToMatch, Value),
            MatchOperator.Regex => System.Text.RegularExpressions.Regex.IsMatch(valueToMatch, Value),
            _ => false
        };
    }

    private static bool MatchWildcard(string input, string pattern)
    {
        // Convert wildcard pattern to regex
        pattern = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*\\*", ".*")
            .Replace("\\*", "[^\\\\]*") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(input, pattern);
    }

    public bool Equals(FingerPrint? other)
    {
        if (other is null) return false;

        var thisValue = Type switch
        {
            FingerprintType.FullPath or FingerprintType.CommandLine =>
                Environment.ExpandEnvironmentVariables(Value),
            _ => Value
        };

        var otherValue = other.Type switch
        {
            FingerprintType.FullPath or FingerprintType.CommandLine =>
                Environment.ExpandEnvironmentVariables(other.Value),
            _ => other.Value
        };

        return Type == other.Type &&
               Operator == other.Operator &&
               thisValue.Equals(otherValue, StringComparison.OrdinalIgnoreCase);
    }

    public override bool Equals(object? obj) => Equals(obj as FingerPrint);

    public override int GetHashCode() => HashCode.Combine(Type, Operator, Value.ToLowerInvariant());
}

/// <summary>
/// Types of process properties that can be matched
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FingerprintType
{
    FullPath,
    ProcessName,
    CommandLine,
    WindowsStore,
    WindowsService
}

/// <summary>
/// Comparison operators available for fingerprint matching
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MatchOperator
{
    Equals,
    StartsWith,
    Contains,
    Wildcard,
    Regex
}
