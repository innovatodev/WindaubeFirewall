using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Binding = System.Windows.Data.Binding;
using TabControl = System.Windows.Controls.TabControl;

using System.ComponentModel;
using System.Windows.Data;
using System.Net;

namespace WindaubeFirewall.Connection;

public class ConnectionStoreWindow : Window, IDisposable
{
    private static ConnectionStoreWindow? _instance;
    private static readonly object _lock = new();
    private bool _disposed;
    private DateTime _lastUpdate = DateTime.MinValue;
    private readonly HashSet<string> _activeConnectionIds = [];
    private readonly HashSet<string> _endedConnectionIds = [];
    private readonly HashSet<string> _activeDnsConnectionIds = [];
    private readonly HashSet<string> _endedDnsConnectionIds = [];
    private int _activeTabIndex = 0;

    public static void Initialize()
    {
        if (_instance == null)
        {
            lock (_lock)
            {
                if (_instance == null)
                {
                    _instance = new ConnectionStoreWindow();
                    _instance.Show();
                }
            }
        }
        else
        {
            _instance.Activate();
        }
    }

    private readonly DispatcherTimer _updateTimer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private readonly ObservableCollection<ConnectionModel> _activeConnections = [];
    private readonly ObservableCollection<ConnectionModel> _endedConnections = [];
    private readonly ObservableCollection<ConnectionModel> _activeDnsConnections = [];
    private readonly ObservableCollection<ConnectionModel> _endedDnsConnections = [];
    private readonly ListCollectionView _activeConnectionsView;
    private readonly ListCollectionView _endedConnectionsView;
    private readonly ListCollectionView _activeDnsConnectionsView;
    private readonly ListCollectionView _endedDnsConnectionsView;

    private ConnectionStoreWindow()
    {
        Title = "ConnectionWindow";
        Width = 1800;
        Height = 720;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        // Initialize collection views with sorting
        _activeConnectionsView = CreateSortedView(_activeConnections, "StartDate", ListSortDirection.Descending);
        _endedConnectionsView = CreateSortedView(_endedConnections, "EndDate", ListSortDirection.Descending);
        _activeDnsConnectionsView = CreateSortedView(_activeDnsConnections, "StartDate", ListSortDirection.Descending);
        _endedDnsConnectionsView = CreateSortedView(_endedDnsConnections, "EndDate", ListSortDirection.Descending);

        var tabControl = new TabControl();
        tabControl.SelectionChanged += TabControl_SelectionChanged;

        // Create tabs using helper methods
        tabControl.Items.Add(CreateTab("Active Connections", CreateConnectionGrid(_activeConnectionsView)));
        tabControl.Items.Add(CreateTab("Ended Connections", CreateConnectionGrid(_endedConnectionsView, true)));
        tabControl.Items.Add(CreateTab("Active DNS", CreateDnsGrid(_activeDnsConnectionsView)));
        tabControl.Items.Add(CreateTab("Ended DNS", CreateDnsGrid(_endedDnsConnectionsView, true)));

        Content = tabControl;

        InitializeTimer();
        Closed += OnWindowClosed;
    }

    private ListCollectionView CreateSortedView(ObservableCollection<ConnectionModel> collection, string sortProperty, ListSortDirection direction)
    {
        var view = new ListCollectionView(collection);
        view.SortDescriptions.Add(new SortDescription(sortProperty, direction));
        return view;
    }

    private TabItem CreateTab(string header, UIElement content)
    {
        return new TabItem { Header = header, Content = content };
    }

    private DataGrid CreateBaseGrid(ICollectionView itemsSource)
    {
        var grid = new DataGrid
        {
            AutoGenerateColumns = false,
            ItemsSource = itemsSource,
            IsReadOnly = true,
            EnableRowVirtualization = true,
            EnableColumnVirtualization = true
        };
        ScrollViewer.SetIsDeferredScrollingEnabled(grid, true);
        return grid;
    }

    private DataGrid CreateConnectionGrid(ICollectionView itemsSource, bool isEnded = false)
    {
        var grid = CreateBaseGrid(itemsSource);

        AddDurationColumn(grid, isEnded);
        AddBasicColumns(grid);
        AddNetworkColumns(grid);
        AddBandwidthColumns(grid);
        AddLocationColumns(grid);
        AddTimeColumns(grid, isEnded);

        return grid;
    }

    private DataGrid CreateDnsGrid(ICollectionView itemsSource, bool isEnded = false)
    {
        var grid = CreateBaseGrid(itemsSource);

        AddDurationColumn(grid, isEnded);
        AddBasicDnsColumns(grid);
        AddTimeColumns(grid, isEnded);

        return grid;
    }

    private void AddDurationColumn(DataGrid grid, bool isEnded)
    {
        grid.Columns.Add(new DataGridTextColumn
        {
            Header = "D",
            Width = DataGridLength.Auto,
            Binding = isEnded ?
                new MultiBinding
                {
                    Converter = new EndedDurationConverter(),
                    Bindings = {
                        new Binding("StartDate"),
                        new Binding("EndDate")
                    }
                } :
                new Binding() { Path = new PropertyPath("StartDate"), Converter = new ActiveDurationConverter() }
        });
    }

    private void AddBasicColumns(DataGrid grid)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "V", Width = DataGridLength.Auto, Binding = new Binding("VerdictString") });
        grid.Columns.Add(new DataGridTextColumn { Header = "VR", Width = DataGridLength.Auto, Binding = new Binding("VerdictReason") });
        grid.Columns.Add(new DataGridTextColumn { Header = "PID", Width = DataGridLength.Auto, Binding = new Binding("ProcessID") });
        grid.Columns.Add(new DataGridTextColumn { Header = "PName", Width = DataGridLength.Auto, Binding = new Binding("ProcessName") });
    }

    private void AddNetworkColumns(DataGrid grid)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "DIR", Width = DataGridLength.Auto, Binding = new Binding("Direction") { Converter = new DirectionConverter() } });
        grid.Columns.Add(new DataGridTextColumn { Header = "PRO", Width = DataGridLength.Auto, Binding = new Binding("Protocol") { Converter = new ProtocolConverter() } });
        grid.Columns.Add(new DataGridTextColumn { Header = "LIP", Width = DataGridLength.Auto, Binding = new Binding("LocalIP") });
        grid.Columns.Add(new DataGridTextColumn { Header = "LPort", Width = DataGridLength.Auto, Binding = new Binding("LocalPort") });
        grid.Columns.Add(new DataGridTextColumn { Header = "LScope", Width = DataGridLength.Auto, Binding = new Binding("LocalScope") { Converter = new ScopeConverter() } });
        grid.Columns.Add(new DataGridTextColumn { Header = "RIP", Width = DataGridLength.Auto, Binding = new Binding("RemoteIP") });
        grid.Columns.Add(new DataGridTextColumn { Header = "RPort", Width = DataGridLength.Auto, Binding = new Binding("RemotePort") });
        grid.Columns.Add(new DataGridTextColumn { Header = "RScope", Width = DataGridLength.Auto, Binding = new Binding("RemoteScope") { Converter = new ScopeConverter() } });
    }

    private void AddBandwidthColumns(DataGrid grid)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "Received", Width = DataGridLength.Auto, Binding = new Binding("ReceivedBytes") { Converter = new BytesToKBConverter() } });
        grid.Columns.Add(new DataGridTextColumn { Header = "Sent", Width = DataGridLength.Auto, Binding = new Binding("SentBytes") { Converter = new BytesToKBConverter() } });
    }

    private void AddLocationColumns(DataGrid grid)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "CN", Width = DataGridLength.Auto, Binding = new Binding("Country") });
        grid.Columns.Add(new DataGridTextColumn { Header = "ASN", Width = DataGridLength.Auto, Binding = new Binding("ASN") });
        grid.Columns.Add(new DataGridTextColumn { Header = "ORG", Width = DataGridLength.Auto, Binding = new Binding("Organization") });
    }

    private void AddBasicDnsColumns(DataGrid grid)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "V", Width = DataGridLength.Auto, Binding = new Binding("VerdictString") });
        grid.Columns.Add(new DataGridTextColumn { Header = "VR", Width = DataGridLength.Auto, Binding = new Binding("VerdictReason") });
        grid.Columns.Add(new DataGridTextColumn { Header = "PID", Width = DataGridLength.Auto, Binding = new Binding("ProcessID") });
        grid.Columns.Add(new DataGridTextColumn { Header = "PName", Width = DataGridLength.Auto, Binding = new Binding("ProcessName") });
        grid.Columns.Add(new DataGridTextColumn { Header = "LIP", Width = DataGridLength.Auto, Binding = new Binding("LocalIP") });
        grid.Columns.Add(new DataGridTextColumn { Header = "LPort", Width = DataGridLength.Auto, Binding = new Binding("LocalPort") });
        grid.Columns.Add(new DataGridTextColumn { Header = "RIP", Width = DataGridLength.Auto, Binding = new Binding("RemoteIP") });
        grid.Columns.Add(new DataGridTextColumn { Header = "RPort", Width = DataGridLength.Auto, Binding = new Binding("RemotePort") });
    }

    private void AddTimeColumns(DataGrid grid, bool includeEndDate = false)
    {
        grid.Columns.Add(new DataGridTextColumn { Header = "Started", Width = DataGridLength.Auto, Binding = new Binding("StartDate") { Converter = new TimeOnlyConverter() } });
        if (includeEndDate)
        {
            grid.Columns.Add(new DataGridTextColumn { Header = "EndDate", Width = DataGridLength.Auto, Binding = new Binding("EndDate") { Converter = new TimeOnlyConverter() } });
        }
    }

    private void InitializeTimer()
    {
        _updateTimer.Tick += UpdateTimer_Tick;
        _updateTimer.Start();
    }

    private void OnWindowClosed(object? sender, EventArgs e)
    {
        Dispose();
    }

    private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is TabControl tabControl)
        {
            _activeTabIndex = tabControl.SelectedIndex;
        }
    }

    private async void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        var now = DateTime.Now;
        if ((now - _lastUpdate).TotalMilliseconds < 1000) return;
        _lastUpdate = now;

        await Dispatcher.InvokeAsync(() =>
        {
            switch (_activeTabIndex)
            {
                case 0: // Active Connections
                    UpdateActiveConnections();
                    break;
                case 1: // Ended Connections
                    UpdateEndedConnections();
                    break;
                case 2: // Active DNS
                    UpdateActiveDnsConnections();
                    break;
                case 3: // Ended DNS
                    UpdateEndedDnsConnections();
                    break;
            }
        }, DispatcherPriority.Background);
    }

    private void UpdateActiveConnections()
    {
        var connections = ConnectionWorker._connections.Values.Where(c => c.IsActive);
        UpdateCollection(_activeConnections, connections, _activeConnectionIds);
        _activeConnectionsView.Refresh();
    }

    private void UpdateEndedConnections()
    {
        var connections = ConnectionWorker._connections.Values.Where(c => !c.IsActive);
        UpdateCollection(_endedConnections, connections, _endedConnectionIds);
        _endedConnectionsView.Refresh();
    }

    private void UpdateActiveDnsConnections()
    {
        var connections = ConnectionWorker._connectionsDns.Values.Where(c => c.IsActive);
        UpdateCollection(_activeDnsConnections, connections, _activeDnsConnectionIds);
        _activeDnsConnectionsView.Refresh();
    }

    private void UpdateEndedDnsConnections()
    {
        var connections = ConnectionWorker._connectionsDns.Values.Where(c => !c.IsActive);
        UpdateCollection(_endedDnsConnections, connections, _endedDnsConnectionIds);
        _endedDnsConnectionsView.Refresh();
    }

    private void UpdateCollection(ObservableCollection<ConnectionModel> collection, IEnumerable<ConnectionModel> newItems, HashSet<string> idSet)
    {
        var currentIds = new HashSet<string>();
        var toAdd = new List<ConnectionModel>();
        var toRemove = new List<ConnectionModel>();

        foreach (var item in newItems)
        {
            var id = item.GetHashCode().ToString();
            currentIds.Add(id);
            if (!idSet.Contains(id))
            {
                toAdd.Add(item);
                idSet.Add(id);
            }
        }

        foreach (var item in collection)
        {
            var id = item.GetHashCode().ToString();
            if (!currentIds.Contains(id))
            {
                toRemove.Add(item);
                idSet.Remove(id);
            }
        }

        ApplyChanges(collection, toRemove, toAdd);
    }

    private void ApplyChanges(ObservableCollection<ConnectionModel> collection,
                            List<ConnectionModel> itemsToRemove,
                            List<ConnectionModel> itemsToAdd)
    {
        foreach (var item in itemsToRemove)
        {
            collection.Remove(item);
        }
        foreach (var item in itemsToAdd)
        {
            collection.Add(item);
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _activeConnectionIds.Clear();
                _endedConnectionIds.Clear();
                _activeDnsConnectionIds.Clear();
                _endedDnsConnectionIds.Clear();

                // Clean up managed resources
                _updateTimer.Stop();
                _updateTimer.Tick -= UpdateTimer_Tick;

                Closed -= OnWindowClosed;

                _activeConnections.Clear();
                _endedConnections.Clear();
                _activeDnsConnections.Clear();
                _endedDnsConnections.Clear();

                _instance = null;
            }
            _disposed = true;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}

public class CollectionToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        if (value is List<IPAddress> ips)
            return string.Join(", ", ips);
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

public class DirectionConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => StringConverters.DirectionToString((byte)value);
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class ProtocolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => StringConverters.ProtocolToString((byte)value);
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class ScopeConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => StringConverters.IPScopeToString((int)value);
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class ActiveDurationConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        if (value is DateTime startDate)
            return StringConverters.DurationToString(DateTime.Now - startDate);
        return "?";
    }
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class EndedDurationConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        if (values.Length == 2 && values[0] is DateTime startDate && values[1] is DateTime endDate)
            return StringConverters.DurationToString(endDate - startDate);
        return "?";
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class BytesToKBConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        if (value is ulong bytes)
            return StringConverters.BytesToString(bytes);
        return "0";
    }
    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}

public class TimeOnlyConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
    {
        if (value is DateTime dateTime)
            return dateTime.ToString("HH:mm:ss.fff");
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        => throw new NotImplementedException();
}
