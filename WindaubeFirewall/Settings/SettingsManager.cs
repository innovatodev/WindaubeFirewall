using System.IO;

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace WindaubeFirewall.Settings;

public class SettingsManager
{
    private static readonly string AppSettingsPath = Constants.AppSettingsFile;
    private static readonly string ProfilesSettingsPath = Constants.AppProfilesFile;
    private static readonly object _settingsLock = new();
    private const int MaxRetries = 3;
    private const int RetryDelayMs = 100;

    private static readonly ISerializer Serializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .DisableAliases()
        .Build();

    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    public static SettingsApplication LoadSettingsApplication()
    {
        if (!File.Exists(AppSettingsPath))
        {
            var defaultSettings = new SettingsApplication();
            SaveSettingsApplication(defaultSettings);
            return defaultSettings;
        }

        try
        {
            var yaml = File.ReadAllText(AppSettingsPath);
            if (string.IsNullOrWhiteSpace(yaml))
            {
                var defaultSettings = new SettingsApplication();
                SaveSettingsApplication(defaultSettings);
                return defaultSettings;
            }

            var settings = Deserializer.Deserialize<SettingsApplication>(yaml);
            return settings ?? new SettingsApplication();
        }
        catch (Exception ex)
        {
            Logger.Log($"Error loading application settings: {ex}");
            var defaultSettings = new SettingsApplication();
            SaveSettingsApplication(defaultSettings);
            return defaultSettings;
        }
    }

    public static void SaveSettingsApplication(SettingsApplication settings)
    {
        lock (_settingsLock)
        {
            RetryFileOperation(() =>
            {
                var yaml = Serializer.Serialize(settings);
                File.WriteAllText(AppSettingsPath, yaml);
            });
        }
    }

    public static List<SettingsProfiles> LoadSettingsProfiles()
    {
        lock (_settingsLock)
        {
            List<SettingsProfiles> loadedProfiles;

            if (!File.Exists(ProfilesSettingsPath))
            {
                loadedProfiles = new List<SettingsProfiles>();
                SaveSettingsProfiles(loadedProfiles);
            }
            else
            {
                var yaml = File.ReadAllText(ProfilesSettingsPath);
                loadedProfiles = Deserializer.Deserialize<List<SettingsProfiles>>(yaml) ?? new List<SettingsProfiles>();
            }

            return loadedProfiles;
        }
    }

    public static void SaveSettingsProfiles(List<SettingsProfiles> profiles)
    {
        lock (_settingsLock)
        {
            RetryFileOperation(() =>
            {
                using var fileStream = new FileStream(
                    ProfilesSettingsPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.Read);
                using var writer = new StreamWriter(fileStream);
                var yaml = Serializer.Serialize(profiles);
                writer.Write(yaml);
            });
        }
    }

    private static void RetryFileOperation(Action operation)
    {
        Exception? lastException = null;

        for (int i = 0; i < MaxRetries; i++)
        {
            try
            {
                operation();
                return;
            }
            catch (IOException ex)
            {
                lastException = ex;
                if (i < MaxRetries - 1)
                {
                    Thread.Sleep(RetryDelayMs);
                }
            }
        }

        throw new IOException($"Failed to access file after {MaxRetries} attempts", lastException);
    }
}
