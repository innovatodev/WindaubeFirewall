using System.ComponentModel;
using System.Windows;

using WindaubeFirewall.Blocklists;
using WindaubeFirewall.Connection;
using WindaubeFirewall.DnsEventLog;
using WindaubeFirewall.DnsServer;
using WindaubeFirewall.Driver;
using WindaubeFirewall.Network;
using WindaubeFirewall.Profiles;
using WindaubeFirewall.Settings;

namespace WindaubeFirewall;

public partial class App : Application
{
    public static CancellationTokenSource _cancellationTokenSource = new();

    #region  Settings
    public static event EventHandler? SettingsAppChanged;
    public static event EventHandler? SettingsProfilesChanged;
    private static SettingsApplication _settingsApp = SettingsManager.LoadSettingsApplication();
    public static SettingsApplication SettingsApp
    {
        get => _settingsApp;
        set
        {
            if (_settingsApp != value)
            {
                if (_settingsApp != null)
                    _settingsApp.PropertyChanged -= SettingsApp_PropertyChanged;

                _settingsApp = value;
                _settingsApp.PropertyChanged += SettingsApp_PropertyChanged;

                HandleSettingsChange();
            }
        }
    }

    private static List<SettingsProfiles> _settingsProfiles = SettingsManager.LoadSettingsProfiles();
    public static List<SettingsProfiles> SettingsProfiles
    {
        get => _settingsProfiles;
        set
        {
            if (_settingsProfiles != value)
            {
                foreach (var profile in _settingsProfiles)
                    profile.PropertyChanged -= SettingsProfiles_PropertyChanged;

                _settingsProfiles = value;

                foreach (var profile in _settingsProfiles)
                    profile.PropertyChanged += SettingsProfiles_PropertyChanged;

                HandleSettingsChange();
            }
        }
    }

    private static void HandleSettingsChange()
    {
        SettingsManager.SaveSettingsApplication(_settingsApp);
        SettingsManager.SaveSettingsProfiles(_settingsProfiles);
        SettingsAppChanged?.Invoke(null, EventArgs.Empty);
        SettingsProfilesChanged?.Invoke(null, EventArgs.Empty);
    }

    private static void SettingsApp_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        HandleSettingsChange();
    }

    private static void SettingsProfiles_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        HandleSettingsChange();
    }
    #endregion Settings

    private static AppTray? _appTray;

    public static List<string> DnsBlocklistsIP = BlocklistManager.LoadDnsBlocklistsIP();
    public static List<string> DnsBlocklistsDomains = BlocklistManager.LoadDnsBlocklistsDomains();
    public static List<Blocklist> Blocklists = BlocklistManager.LoadBlocklists();
    public static List<NetworkAdapter> NetworkAdapters = [];

    public App()
    {
        // Exceptions
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        // Subscribe to PropertyChanged events
        _settingsApp.PropertyChanged += SettingsApp_PropertyChanged;
        foreach (var profile in _settingsProfiles) profile.PropertyChanged += SettingsProfiles_PropertyChanged;

        ProfilesManager.EnsureSpecialProfiles(SettingsProfiles);
        SettingsManager.SaveSettingsProfiles(SettingsProfiles);

        NetworkAdaptersWorker.Start();
        DnsEventLogWorker.Start();
        DnsServerWorker.Start();
        DriverWorker.Start();
        ConnectionWorker.Start();

        _appTray = new AppTray();

        // Window
        //ConnectionStoreWindow.Initialize();
    }

    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var exception = e.ExceptionObject as Exception;
        HandleFatalError("An unhandled error occurred", exception);
    }

    public void OnDispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
    {
        HandleFatalError("An unhandled error occurred", e.Exception);
    }

    public static void HandleFatalError(string message, Exception? ex)
    {
        Logger.Log($"Fatal error: {message}");
        if (ex is AggregateException aggEx)
        {
            foreach (var innerEx in aggEx.InnerExceptions)
            {
                Logger.Log($"{innerEx}");
            }
        }
        else
        {
            Logger.Log($"{ex}");
        }
        DriverManager.CleanDriver();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _cancellationTokenSource?.Cancel();
        DriverManager.CleanDriver();
        base.OnExit(e);
    }
}
