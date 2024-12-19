namespace WindaubeFirewall.Utils;

public class StringConverters
{
    public static string ProtocolToString(byte protocol)
    {
        return protocol switch
        {
            0 => "HOPOPT",
            1 => "ICMP",
            2 => "IGMP",
            4 => "IPv4",
            6 => "TCP",
            17 => "UDP",
            27 => "RDP",
            33 => "DCCP",
            41 => "IPv6",
            44 => "IPv6-Frag",
            58 => "ICMPv6",
            98 => "EncapsulationHeader",
            136 => "UDPLite",
            _ => $"UnknownProtocol({protocol})",
        };
    }

    public static byte ProtocolFromString(string protocolString)
    {
        return protocolString switch
        {
            "HOPOPT" => 0,
            "ICMP" => 1,
            "IGMP" => 2,
            "IPv4" => 4,
            "TCP" => 6,
            "UDP" => 17,
            "RDP" => 27,
            "DCCP" => 33,
            "IPv6" => 41,
            "IPv6-Frag" => 44,
            "ICMPv6" => 58,
            "EncapsulationHeader" => 98,
            "UDPLite" => 136,
            _ => throw new ArgumentException("UnknownProtocol", nameof(protocolString)),
        };
    }

    public static string DirectionToString(byte direction)
    {
        return direction switch
        {
            0 => "OUT",
            1 => "IN",
            _ => $"UnknownDirection({direction})",
        };
    }

    public static byte DirectionFromString(string directionString)
    {
        return directionString switch
        {
            "OUT" => 0,
            "IN" => 1,
            _ => throw new ArgumentException("UnknownDirection", nameof(directionString)),
        };
    }

    public static string IPScopeToString(int scope)
    {
        return scope switch
        {
            0 => "Localhost",
            1 => "Multicast",
            2 => "LAN",
            3 => "Internet",
            _ => $"UnknownIPScope({scope})",
        };
    }

    public static int IPScopeFromString(string scopeString)
    {
        return scopeString switch
        {
            "Localhost" => 0,
            "Multicast" => 1,
            "LAN" => 2,
            "Internet" => 3,
            _ => throw new ArgumentException("UnknownIPScope", nameof(scopeString)),
        };
    }

    public static string TCPStateToString(uint state)
    {
        return state switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RECEIVED",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT_1",
            7 => "FIN_WAIT_2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => throw new Exception("UnknownTCPState")
        };
    }

    public static uint TCPStateFromString(string stateString)
    {
        return stateString switch
        {
            "CLOSED" => 1,
            "LISTEN" => 2,
            "SYN_SENT" => 3,
            "SYN_RECEIVED" => 4,
            "ESTABLISHED" => 5,
            "FIN_WAIT_1" => 6,
            "FIN_WAIT_2" => 7,
            "CLOSE_WAIT" => 8,
            "CLOSING" => 9,
            "LAST_ACK" => 10,
            "TIME_WAIT" => 11,
            "DELETE_TCB" => 12,
            _ => throw new ArgumentException("UnknownTCPState", nameof(stateString)),
        };
    }

    public static string DriverCommandToString(byte command)
    {
        return command switch
        {
            0 => "Shutdown",
            1 => "Verdict",
            2 => "UpdateV4",
            3 => "UpdateV6",
            4 => "ClearCache",
            5 => "GetLogs",
            6 => "BandwidthStats",
            7 => "PrintMemoryStats",
            8 => "CleanEndedConnections",
            _ => $"UnknownCommand({command})",
        };
    }

    public static byte DriverCommandFromString(string commandString)
    {
        return commandString switch
        {
            "Shutdown" => 0,
            "Verdict" => 1,
            "UpdateV4" => 2,
            "UpdateV6" => 3,
            "ClearCache" => 4,
            "GetLogs" => 5,
            "BandwidthStats" => 6,
            "PrintMemoryStats" => 7,
            "CleanEndedConnections" => 8,
            _ => throw new ArgumentException("UnknownCommand", nameof(commandString)),
        };
    }

    public static string DriverVerdictToString(byte verdict)
    {
        return verdict switch
        {
            0 => "Undecided",
            1 => "Undeterminable",
            2 => "Accept",
            3 => "PermanentAccept",
            4 => "Block",
            5 => "PermanentBlock",
            6 => "Drop",
            7 => "PermanentDrop",
            8 => "RerouteToNameserver",
            9 => "RerouteToTunnel",
            10 => "Failed",
            _ => $"UnknownVerdict({verdict})",
        };
    }

    public static byte DriverVerdictFromString(string verdictString)
    {
        return verdictString switch
        {
            "Undecided" => 0,
            "Undeterminable" => 1,
            "Accept" => 2,
            "PermanentAccept" => 3,
            "Block" => 4,
            "PermanentBlock" => 5,
            "Drop" => 6,
            "PermanentDrop" => 7,
            "RerouteToNameserver" => 8,
            "RerouteToTunnel" => 9,
            "Failed" => 10,
            _ => throw new ArgumentException("UnknownVerdict", nameof(verdictString)),
        };
    }

    public static string DecisionToString(byte decision)
    {
        return decision switch
        {
            0 => "BLOCK",
            1 => "ALLOW",
            2 => "PROMPT",
            _ => $"UnknownDecision({decision})",
        };
    }

    public static byte DecisionFromString(string decisionString)
    {
        return decisionString switch
        {
            "BLOCK" => 0,
            "ALLOW" => 1,
            "PROMPT" => 2,
            _ => throw new ArgumentException("UnknownDecision", nameof(decisionString)),
        };
    }

    public static string FingerprintTypeToString(byte fingerprintType)
    {
        return fingerprintType switch
        {
            0 => "FullPath",
            1 => "ProcessName",
            2 => "CommandLine",
            3 => "WindowsStore",
            4 => "WindowsService",
            _ => $"UnknownFingerprintType({fingerprintType})",
        };
    }

    public static byte FingerprintTypeFromString(string fingerprintTypeString)
    {
        return fingerprintTypeString switch
        {
            "FullPath" => 0,
            "ProcessName" => 1,
            "CommandLine" => 2,
            "WindowsStore" => 3,
            "WindowsService" => 4,
            _ => throw new ArgumentException("UnknownFingerprintType", nameof(fingerprintTypeString)),
        };
    }

    public static string FingerprintMatchOperatorToString(byte matchOperator)
    {
        return matchOperator switch
        {
            0 => "Equals",
            1 => "StartsWith",
            2 => "Contains",
            3 => "Wildcard",
            4 => "Regex",
            _ => $"UnknownMatchOperator({matchOperator})",
        };
    }

    public static byte FingerprintMatchOperatorFromString(string matchOperatorString)
    {
        return matchOperatorString switch
        {
            "Equals" => 0,
            "StartsWith" => 1,
            "Contains" => 2,
            "Wildcard" => 3,
            "Regex" => 4,
            _ => throw new ArgumentException("UnknownMatchOperator", nameof(matchOperatorString)),
        };
    }

    public static string BytesToString(ulong bytes)
    {
        const ulong KB = 1024;
        const ulong MB = KB * 1024;
        const ulong GB = MB * 1024;

        return bytes switch
        {
            < KB => $"{bytes}B",
            < MB => $"{bytes / (double)KB:F2}KB",
            < GB => $"{bytes / (double)MB:F2}MB",
            _ => $"{bytes / (double)GB:F1}GB"
        };
    }

    public static string DurationToString(TimeSpan duration)
    {
        if (duration.TotalMilliseconds < 1000)
            return $"{duration.TotalMilliseconds:0}ms";
        if (duration.TotalSeconds < 60)
            return $"{duration.TotalSeconds:0}s";
        if (duration.TotalMinutes < 60)
            return $"{(int)duration.TotalMinutes}m{duration.Seconds}s";
        if (duration.TotalHours < 24)
            return $"{(int)duration.TotalHours}h{duration.Minutes}m{duration.Seconds}s";
        if (duration.TotalDays < 30)
            return $"{(int)duration.TotalDays}d{duration.Hours}h{duration.Minutes}m{duration.Seconds}s";
        return $"{(int)duration.TotalDays}d{duration.Hours}h{duration.Minutes}m{duration.Seconds}s";
    }
}
