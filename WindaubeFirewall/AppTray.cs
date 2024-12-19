using Hardcodet.Wpf.TaskbarNotification;

using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using WindaubeFirewall.Connection;
using WindaubeFirewall.Driver;

namespace WindaubeFirewall;

public class AppTray : IDisposable
{
    private readonly TaskbarIcon? _notifyIcon;
    private readonly MenuItem _dnsServerToggle;

    public AppTray()
    {
        var contextMenu = new ContextMenu();

        // DriverCommands
        var driverCommandsMenu = new MenuItem { Header = "Driver Commands" };
        var getBandwidthItem = new MenuItem { Header = "GetBandwidth" };
        getBandwidthItem.Click += GetBandwidth_Click;
        driverCommandsMenu.Items.Add(getBandwidthItem);
        contextMenu.Items.Add(driverCommandsMenu);

        // DNS Server Toggle
        _dnsServerToggle = new MenuItem { Header = "DNSServer" };
        _dnsServerToggle.Click += DnsServerToggle_Click;
        UpdateDnsServerToggleState();
        contextMenu.Items.Add(_dnsServerToggle);

        // Exit
        var exitItem = new MenuItem { Header = "Exit", };
        exitItem.Click += Exit_Click;
        contextMenu.Items.Add(exitItem);

        // Icon
        var iconUri = new Uri(Constants.AppIcon, UriKind.RelativeOrAbsolute);
        var bitmap = new BitmapImage(iconUri);

        // Initialize
        _notifyIcon = new TaskbarIcon
        {
            IconSource = bitmap,
            ToolTipText = "WindaubeFirewall",
            ContextMenu = contextMenu
        };
        _notifyIcon.TrayMouseDoubleClick += OnTrayDoubleClick;

        App.SettingsAppChanged += OnSettingsChanged;
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
    {
        if (Application.Current.Dispatcher.CheckAccess())
        {
            UpdateDnsServerToggleState();
        }
        else
        {
            Application.Current.Dispatcher.BeginInvoke(() => UpdateDnsServerToggleState());
        }
    }

    private void UpdateDnsServerToggleState()
    {
        if (Application.Current.Dispatcher.CheckAccess())
        {
            _dnsServerToggle.IsChecked = DnsServer.DnsServerWorker.IsEnabled;
        }
        else
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _dnsServerToggle.IsChecked = DnsServer.DnsServerWorker.IsEnabled;
            });
        }
    }

    private void DnsServerToggle_Click(object sender, RoutedEventArgs e)
    {
        if (DnsServer.DnsServerWorker.IsEnabled)
        {
            DnsServer.DnsServerWorker.Disable();
            App.SettingsApp.DnsServer.IsEnabled = false;
        }
        else
        {
            DnsServer.DnsServerWorker.Enable();
            App.SettingsApp.DnsServer.IsEnabled = true;
        }
        UpdateDnsServerToggleState();
    }

    private void GetBandwidth_Click(object sender, RoutedEventArgs e)
    {
        DriverInfoSender.CommandGetBandwidthStats();
        throw new NotImplementedException();
    }

    private void Exit_Click(object sender, RoutedEventArgs e)
    {
        Application.Current.Shutdown();
    }

    private void OnTrayDoubleClick(object? sender, RoutedEventArgs e)
    {
        ConnectionStoreWindow.Initialize();
    }

    public void Dispose()
    {
        _notifyIcon?.Dispose();
        GC.SuppressFinalize(this);
    }
}
