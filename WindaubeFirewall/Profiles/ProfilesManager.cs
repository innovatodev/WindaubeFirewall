using WindaubeFirewall.Settings;
using WindaubeFirewall.ProcessInfos;
using WindaubeFirewall.Connection;
using WindaubeFirewall.Blocklists;

namespace WindaubeFirewall.Profiles;

public class ProfilesManager
{
    public static void EnsureSpecialProfiles(List<SettingsProfiles> profiles)
    {
        // Define default special profiles
        var defaultProfiles = new List<SettingsProfiles>
        {
            new() {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000001"),
                Name = "WindaubeFirewall",
                IsSpecial = true,
                IsAutoGenerated = true,
                Icon = ProcessInfo.ICON_WINDAUBEFIREWALL,
                Fingerprints =
                [
                    new() { Type = FingerprintType.FullPath, Operator = MatchOperator.Equals, Value = Environment.ProcessPath ?? $"{AppContext.BaseDirectory}\\WindaubeFirewall.exe" }
                ],
                NetworkAction = new NetworkActionSettings
                {
                    DefaultNetworkAction = 1,
                    ForceBlockInternet = false,
                    ForceBlockLAN = false,
                    ForceBlockLocalhost = false,
                    ForceBlockIncoming = false,
                    BlockBypassDNS = false,
                }
            },
            new() {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000002"),
                Name = "SystemDNS",
                IsSpecial = true,
                IsAutoGenerated = true,
                Icon = ProcessInfo.ICON_DEFAULT_PROCESS,
                Fingerprints =
                [
                    new() { Type = FingerprintType.WindowsService, Operator = MatchOperator.Equals, Value = "Dnscache" }
                ],
                NetworkAction = new NetworkActionSettings
                {
                    DefaultNetworkAction = 0,
                    ForceBlockInternet = false,
                    ForceBlockLAN = false,
                    ForceBlockLocalhost = false,
                    ForceBlockIncoming = false,
                    IncomingRules =
                    [
                        "ALLOW Localhost",
                        "ALLOW LAN UDP/5353",
                        "ALLOW LAN UDP/5355",
                        "ALLOW MULTICAST UDP/5353",
                        "ALLOW MULTICAST UDP/5355",
                        "BLOCK *"
                    ],
                    OutgoingRules =
                    [
                        "ALLOW Localhost",
                        "ALLOW LAN UDP/5353",
                        "ALLOW LAN UDP/5355",
                        "ALLOW MULTICAST UDP/5353",
                        "ALLOW MULTICAST UDP/5355",
                        "ALLOW * UDP/53",
                        "ALLOW * TCP/443",
                        "ALLOW * TCP/853",
                        "BLOCK *"
                    ]
                }
            },
            new() {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000003"),
                Name = "SYSTEM",
                IsSpecial = true,
                IsAutoGenerated = true,
                Icon = ProcessInfo.ICON_DEFAULT_PROCESS,
                Fingerprints =
                [
                    new() { Type = FingerprintType.ProcessName, Operator = MatchOperator.Equals, Value = "SYSTEM" },
                    new() { Type = FingerprintType.ProcessName, Operator = MatchOperator.Equals, Value = "IDLE" }
                ],
                NetworkAction = new NetworkActionSettings
                {
                    DefaultNetworkAction = 0,
                    ForceBlockInternet = false,
                    ForceBlockLAN = false,
                    ForceBlockLocalhost = false,
                    ForceBlockIncoming = false,
                    IncomingRules =
                    [
                      //
                    ],
                    OutgoingRules =
                    [
                      //
                    ]
                }
            },
            new() {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000004"),
                Name = "UNKNOWN",
                IsSpecial = true,
                IsAutoGenerated = true,
                Icon = ProcessInfo.ICON_UNKNOWN,
                Fingerprints =
                [
                    new() { Type = FingerprintType.ProcessName, Operator = MatchOperator.Equals, Value = "UNKNOWN" }
                ],
                NetworkAction = new NetworkActionSettings
                {
                    //
                }
            }
        };

        foreach (var defaultProfile in defaultProfiles)
        {
            if (!profiles.Any(p => p.IsSpecial && p.Name == defaultProfile.Name))
            {
                profiles.Add(defaultProfile);
                Logger.Log($"ProfilesManager: Added special profile: {defaultProfile.Name}");
            }
        }
    }

    public static void AddProfile(SettingsProfiles profile)
    {
        var profiles = SettingsManager.LoadSettingsProfiles();

        if (!profiles.Any(p => p.Id == profile.Id))
        {
            profiles.Add(profile);
            App.SettingsProfiles = profiles;
            SettingsManager.SaveSettingsProfiles(profiles);
            Logger.Log($"ProfilesManager: Added profile: {profile.Name}");
        }
        else
        {
            Logger.Log($"ProfilesManager: Profile with ID {profile.Id} already exists.");
        }
    }

    public static SettingsProfiles? MatchConnection(ConnectionModel connection)
    {
        var profiles = App.SettingsProfiles;

        // Check for special profiles first
        if (connection.ProcessName == "SYSTEM" || connection.ProcessName == "IDLE")
        {
            return profiles.First(p => p.IsSpecial && p.Name == "SYSTEM");
        }
        if (connection.ProcessName == "UNKNOWN")
        {
            return profiles.First(p => p.IsSpecial && p.Name == "UNKNOWN");
        }

        return profiles.FirstOrDefault(p => p.Fingerprints.Any(f => MatchesFingerprint(f, connection)));
    }

    private static bool MatchesFingerprint(FingerPrint fingerprint, ConnectionModel connection)
    {
        return fingerprint.Type switch
        {
            FingerprintType.ProcessName => MatchValue(fingerprint.Operator, connection.ProcessName, fingerprint.Value),
            FingerprintType.FullPath => MatchValue(fingerprint.Operator, connection.ProcessPath, fingerprint.Value),
            FingerprintType.WindowsService => MatchValue(fingerprint.Operator,
                connection.ProcessName.StartsWith("SVC:") ? connection.ProcessName[4..] : "", fingerprint.Value),
            FingerprintType.WindowsStore => MatchValue(fingerprint.Operator,
                connection.ProcessName.StartsWith("WinStore:") ? connection.ProcessName[9..] : "", fingerprint.Value),
            _ => false
        };
    }

    private static bool MatchValue(MatchOperator op, string value, string pattern)
    {
        return op switch
        {
            MatchOperator.Equals => value.Equals(pattern, StringComparison.OrdinalIgnoreCase),
            MatchOperator.StartsWith => value.StartsWith(pattern, StringComparison.OrdinalIgnoreCase),
            MatchOperator.Contains => value.Contains(pattern, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    public static SettingsProfiles CreateDefaultProfile(ConnectionModel connection)
    {
        var icon = ProcessInfo.GetProcessIconBase64(connection.ProcessPath);

        // Determine the type of process and create appropriate fingerprint
        FingerPrint fingerprint;
        if (connection.ProcessName.StartsWith("SVC:"))
        {
            var serviceName = connection.ProcessName[4..];
            if (serviceName.Contains('_'))
            {
                serviceName = serviceName[..serviceName.LastIndexOf('_')];
                fingerprint = new FingerPrint
                {
                    Type = FingerprintType.WindowsService,
                    Operator = MatchOperator.StartsWith,
                    Value = serviceName
                };
            }
            else
            {
                fingerprint = new FingerPrint
                {
                    Type = FingerprintType.WindowsService,
                    Operator = MatchOperator.Equals,
                    Value = serviceName
                };
            }
        }
        else if (connection.ProcessName.StartsWith("WinStore:"))
        {
            var storeName = connection.ProcessName[9..];
            fingerprint = new FingerPrint
            {
                Type = FingerprintType.WindowsStore,
                Operator = MatchOperator.Equals,
                Value = storeName
            };
        }
        else
        {
            fingerprint = new FingerPrint
            {
                Type = FingerprintType.FullPath,
                Operator = MatchOperator.Equals,
                Value = connection.ProcessPath
            };
        }

        var profiles = App.SettingsProfiles;
        var existingProfile = profiles.FirstOrDefault(p => p.Fingerprints.Any(f => f.Equals(fingerprint)));
        if (existingProfile != null)
        {
            return existingProfile;
        }

        var newProfile = new SettingsProfiles
        {
            Id = Guid.NewGuid(),
            IsAutoGenerated = true,
            Name = connection.ProcessName.StartsWith("SVC:")
                ? $"SVC:{connection.ProcessName[4..]}"
                : connection.ProcessName,
            Fingerprints = [fingerprint],
            Icon = icon,
            // Initialize blocklists from application settings
            Blocklists = new BlocklistsSettings
            {
                OfflineBlocklists = App.SettingsApp.Blocklists.OfflineBlocklists
                    .Select(ol => new OfflineBlocklistEnabledState { Name = ol.Name, IsEnabled = ol.IsEnabled })
                    .ToList(),
                OnlineBlocklists = App.SettingsApp.Blocklists.OnlineBlocklists
                    .Select(ol => new BlocklistEnabledState { Name = ol.Name, IsEnabled = ol.IsEnabled })
                    .ToList()
            }
        };

        return newProfile;
    }

    public static SettingsProfiles? MatchProcessInfo(string processName, string processPath, string processCommandLine)
    {
        var profiles = App.SettingsProfiles;

        // Check for special profiles first
        if (processName == "SYSTEM" || processName == "IDLE")
        {
            return profiles.First(p => p.IsSpecial && p.Name == "SYSTEM");
        }
        if (processName == "UNKNOWN")
        {
            return profiles.First(p => p.IsSpecial && p.Name == "UNKNOWN");
        }

        return profiles.FirstOrDefault(p => p.Fingerprints.Any(f => MatchesFingerprintProcessInfo(f, processName, processPath)));
    }

    private static bool MatchesFingerprintProcessInfo(FingerPrint fingerprint, string processName, string processPath)
    {
        return fingerprint.Type switch
        {
            FingerprintType.ProcessName => MatchValue(fingerprint.Operator, processName, fingerprint.Value),
            FingerprintType.FullPath => MatchValue(fingerprint.Operator, processPath, fingerprint.Value),
            FingerprintType.WindowsService => MatchValue(fingerprint.Operator,
                processName.StartsWith("SVC:") ? processName[4..] : "", fingerprint.Value),
            FingerprintType.WindowsStore => MatchValue(fingerprint.Operator,
                processName.StartsWith("WinStore:") ? processName[9..] : "", fingerprint.Value),
            _ => false
        };
    }

    public static SettingsProfiles CreateDefaultProfileProcessInfo(string processName, string processPath, string processCommandLine)
    {
        var icon = ProcessInfo.GetProcessIconBase64(processPath);

        // Determine the type of process and create appropriate fingerprint
        FingerPrint fingerprint;
        if (processName.StartsWith("SVC:"))
        {
            var serviceName = processName[4..];
            if (serviceName.Contains('_'))
            {
                serviceName = serviceName[..serviceName.LastIndexOf('_')];
                fingerprint = new FingerPrint
                {
                    Type = FingerprintType.WindowsService,
                    Operator = MatchOperator.StartsWith,
                    Value = serviceName
                };
            }
            else
            {
                fingerprint = new FingerPrint
                {
                    Type = FingerprintType.WindowsService,
                    Operator = MatchOperator.Equals,
                    Value = serviceName
                };
            }
        }
        else if (processName.StartsWith("WinStore:"))
        {
            var storeName = processName[9..];
            fingerprint = new FingerPrint
            {
                Type = FingerprintType.WindowsStore,
                Operator = MatchOperator.Equals,
                Value = storeName
            };
        }
        else
        {
            fingerprint = new FingerPrint
            {
                Type = FingerprintType.FullPath,
                Operator = MatchOperator.Equals,
                Value = processPath
            };
        }

        var profiles = App.SettingsProfiles;
        var existingProfile = profiles.FirstOrDefault(p => p.Fingerprints.Any(f => f.Equals(fingerprint)));
        if (existingProfile != null)
        {
            return existingProfile;
        }

        return new SettingsProfiles
        {
            Id = Guid.NewGuid(),
            IsAutoGenerated = true,
            Name = processName.StartsWith("SVC:")
                ? $"SVC:{processName[4..]}"
                : processName,
            Fingerprints = [fingerprint],
            Icon = icon,
            // Initialize blocklists from application settings
            Blocklists = new BlocklistsSettings
            {
                OfflineBlocklists = App.SettingsApp.Blocklists.OfflineBlocklists
                    .Select(ol => new OfflineBlocklistEnabledState { Name = ol.Name, IsEnabled = ol.IsEnabled })
                    .ToList(),
                OnlineBlocklists = App.SettingsApp.Blocklists.OnlineBlocklists
                    .Select(ol => new BlocklistEnabledState { Name = ol.Name, IsEnabled = ol.IsEnabled })
                    .ToList()
            }
        };
    }
}
