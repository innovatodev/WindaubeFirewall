using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace WindaubeFirewall.Settings;

public class SettingsManager
{
    private static readonly string AppSettingsPath = Constants.AppSettingsFile;
    private static readonly string ProfilesSettingsPath = Constants.AppProfilesFile;

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
        try
        {
            var yaml = Serializer.Serialize(settings);
            File.WriteAllText(AppSettingsPath, yaml);
        }
        catch (Exception ex)
        {
            Logger.Log($"Error saving application settings: {ex}");
            throw;
        }
    }

    public static List<SettingsProfiles> LoadSettingsProfiles()
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
            SaveSettingsProfiles(loadedProfiles);
        }

        return loadedProfiles;
    }

    public static void SaveSettingsProfiles(List<SettingsProfiles> profiles)
    {
        var yaml = Serializer.Serialize(profiles);
        File.WriteAllText(ProfilesSettingsPath, yaml);
    }
}
