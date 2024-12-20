using System.IO;

using YamlDotNet.Core;
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

    private static readonly ISerializer _serializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        // Disable YAML anchors
        .DisableAliases()
        .Build();

    private static readonly IDeserializer _deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .Build();

    private static readonly ISerializer _appSerializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.Preserve)
        // Disable YAML anchors
        .DisableAliases()
        .Build();

    private static readonly ISerializer _profileSerializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.Preserve) // Already preserving nulls
                                                                        // Disable YAML anchors
        .DisableAliases()
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

            var settings = _deserializer.Deserialize<SettingsApplication>(yaml);
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

    public static SettingsApplication CurrentSettingsApplication { get; private set; } = LoadSettingsApplication();

    public static void SaveSettingsApplication(SettingsApplication settings)
    {
        lock (_settingsLock)
        {
            SaveYamlFile(AppSettingsPath, settings, _appSerializer);
        }
    }

    public static List<SettingsProfiles> LoadSettingsProfiles()
    {
        lock (_settingsLock)
        {
            var loadedProfiles = LoadYamlFile<List<SettingsProfiles>>(ProfilesSettingsPath);
            // Avoid adding duplicate profiles
            //foreach (var profile in loadedProfiles)
            //{
            //    if (!SettingsProfiles.Any(p => p.Id == profile.Id))
            //    {
            //        SettingsProfiles.Add(profile);
            //    }
            //}
            return loadedProfiles;
        }
    }

    public static void SaveSettingsProfiles(List<SettingsProfiles> profiles)
    {
        lock (_settingsLock)
        {
            SaveYamlFile(ProfilesSettingsPath, profiles, _profileSerializer);
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

    private static void SaveYamlFile<T>(string path, T data)
    {
        RetryFileOperation(() =>
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var yaml = _serializer.Serialize(data);
            File.WriteAllText(path, yaml);
        });
    }

    private static void SaveYamlFile<T>(string path, T data, ISerializer serializer)
    {
        RetryFileOperation(() =>
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var yaml = serializer.Serialize(data);
            File.WriteAllText(path, yaml);
        });
    }

    private static T LoadYamlFile<T>(string path) where T : new()
    {
        if (!File.Exists(path))
            return new T();

        try
        {
            var yaml = File.ReadAllText(path);
            return _deserializer.Deserialize<T>(yaml);
        }
        catch
        {
            return new T();
        }
    }
}
