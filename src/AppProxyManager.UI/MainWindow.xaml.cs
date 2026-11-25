using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AppProxyManager.Core;
using AppProxyManager.Engine;
using Microsoft.Win32;

namespace AppProxyManager.UI;

public sealed class AppItemVm : INotifyPropertyChanged
{
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public string FileName { get; init; } = "";
    public ImageSource? Icon { get; init; }
    private string _status = "";
    private Brush _brush = Brushes.Gray;
    public string Status { get => _status; set { if (_status != value) { _status = value; Raise(nameof(Status)); } } }
    public Brush StatusBrush { get => _brush; set { if (!ReferenceEquals(_brush, value)) { _brush = value; Raise(nameof(StatusBrush)); } } }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Raise(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}

public partial class MainWindow : Window
{
    private readonly AppController _c;
    private readonly ObservableCollection<AppItemVm> _items = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private bool _loading;
    private bool _exitRequested;
    private readonly System.Windows.Forms.NotifyIcon _trayIcon;

    public MainWindow(AppController controller)
    {
        InitializeComponent();
        _c = controller;
        _trayIcon = CreateTrayIcon();
        AppList.ItemsSource = _items;
        LoadProxyFields();
        RebuildList();

        foreach (var tb in new[] { TxtHost, TxtPort, TxtUser }) tb.LostFocus += (_, _) => CommitProxyFields(false);
        PwdBox.LostFocus += (_, _) => CommitProxyFields(false);
        RbSocks.Checked += (_, _) => CommitProxyFields(false);
        RbHttp.Checked += (_, _) => CommitProxyFields(false);

        _c.StateChanged += () => Dispatcher.BeginInvoke(new Action(UpdateState));
        _timer.Tick += (_, _) => UpdateState();
        _timer.Start();
        Drop += OnDropFiles;
        Closing += OnClosing;
        UpdateState();
    }

    // ---------------------------------------------------------------- proxy fields

    private void LoadProxyFields()
    {
        _loading = true;
        var p = _c.Config.Proxy;
        TxtHost.Text = p.Host; TxtPort.Text = p.Port.ToString(); TxtUser.Text = p.Username ?? ""; PwdBox.Password = p.Password ?? "";
        RbSocks.IsChecked = p.Type == ProxyType.Socks5; RbHttp.IsChecked = p.Type == ProxyType.Http;
        _loading = false;
    }

    /// <summary>Validates the fields and stores them. Returns false (and tells the user) when the input is invalid.</summary>
    private bool CommitProxyFields(bool showErrors)
    {
        if (_loading) return true;
        var p = _c.Config.Proxy;
        string host = TxtHost.Text.Trim();
        if (host.Length == 0 || host.Any(char.IsWhiteSpace)) return Invalid("Enter a proxy host name or IP address.", showErrors);
        if (!int.TryParse(TxtPort.Text.Trim(), out int port) || port is < 1 or > 65535) return Invalid("The port must be a number between 1 and 65535.", showErrors);
        var type = RbHttp.IsChecked == true ? ProxyType.Http : ProxyType.Socks5;
        string? user = string.IsNullOrWhiteSpace(TxtUser.Text) ? null : TxtUser.Text.Trim();
        string? pass = PwdBox.Password.Length == 0 ? null : PwdBox.Password;
        bool changed = p.Host != host || p.Port != port || p.Type != type || p.Username != user || p.Password != pass;
        p.Host = host; p.Port = port; p.Type = type; p.Username = user; p.Password = pass;
        if (changed) _c.ConfigChanged();
        return true;
    }

    private bool Invalid(string msg, bool show)
    {
        if (show) MessageBox.Show(this, msg, "Proxy settings", MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private async void BtnTest_Click(object sender, RoutedEventArgs e)
    {
        if (!CommitProxyFields(true)) return;
        BtnTest.IsEnabled = false;
        SetProxyStatus("Testing…", (Brush)FindResource("Warn"));
        try
        {
            var r = await ProxyHealth.TestAsync(_c.Config.Proxy.Clone(), CancellationToken.None);
            string text = r.Ok ? $"{r.Message}  ({r.LatencyMs} ms)" : r.Message;
            SetProxyStatus(text, (Brush)FindResource(r.Ok ? (r.ExitIp != null ? "Good" : "Warn") : "Bad"));
            _c.Log.Info("Test connection: " + text);
        }
        finally { BtnTest.IsEnabled = true; }
    }

    private void SetProxyStatus(string text, Brush dot) { TxtProxyStatus.Text = text; ProxyDot.Fill = dot; }

    // ---------------------------------------------------------------- application list

    private void RebuildList()
    {
        _items.Clear();
        foreach (var a in _c.Config.Apps)
            _items.Add(new AppItemVm { Path = a.Path, Name = a.DisplayName, FileName = a.FileName, Icon = IconFor(a.Path) });
        TxtEmpty.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static ImageSource? IconFor(string path)
    {
        try
        {
            using var ic = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (ic == null) return null;
            var bs = Imaging.CreateBitmapSourceFromHIcon(ic.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            bs.Freeze();
            return bs;
        }
        catch { return null; }
    }

    private void BtnAdd_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Select applications", Filter = "Applications (*.exe)|*.exe", Multiselect = true, CheckFileExists = true };
        if (dlg.ShowDialog(this) == true) AddFiles(dlg.FileNames);
    }

    private void OnDropFiles(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files) AddFiles(files);
    }

    private void AddFiles(IEnumerable<string> files)
    {
        var r = _c.AddApps(files);
        if (r.Added > 0) RebuildList();
        var notes = new List<string>();
        if (r.Duplicates.Count > 0) notes.Add("Already in the list:\n  " + string.Join("\n  ", r.Duplicates.Select(System.IO.Path.GetFileName)));
        if (r.Rejected.Count > 0) notes.Add("Not added (not an existing .exe):\n  " + string.Join("\n  ", r.Rejected));
        if (notes.Count > 0) MessageBox.Show(this, string.Join("\n\n", notes), "Add application", MessageBoxButton.OK, MessageBoxImage.Information);
        UpdateState();
    }

    private void BtnRemove_Click(object sender, RoutedEventArgs e)
    {
        var sel = AppList.SelectedItems.Cast<AppItemVm>().Select(i => i.Path).ToList();
        if (sel.Count == 0) { MessageBox.Show(this, "Select one or more applications first.", "Remove", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        _c.RemoveApps(sel); RebuildList(); UpdateState();
    }

    private void BtnRemoveOne_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string path }) { _c.RemoveApps(new[] { path }); RebuildList(); UpdateState(); }
    }

    // ---------------------------------------------------------------- routing

    private void BtnStart_Click(object sender, RoutedEventArgs e) => StartRouting(silent: false);

    public void StartRoutingFromCommandLine(bool silent) => StartRouting(silent);

    private void StartRouting(bool silent)
    {
        if (!CommitProxyFields(!silent)) return;
        if (_c.Config.Apps.Count == 0)
        {
            if (!silent) MessageBox.Show(this, "Add at least one application first.", "Start routing", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var r = _c.StartRouting();
        if (r.NeedsElevation)
        {
            var ask = MessageBox.Show(this,
                "Routing needs administrator rights to load the WinDivert network driver.\n\n" +
                "The application will restart with elevated rights and start routing automatically. Continue?",
                "Administrator rights required", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (ask == MessageBoxResult.Yes)
            {
                _c.Save();
                if (Elevation.RestartElevated("--start"))
                {
                    PrepareForApplicationShutdown();
                    Application.Current.Shutdown();
                }

            }
        }
        else if (!r.Ok && !silent)
            MessageBox.Show(this, r.Error ?? "Routing could not be started.", "Start routing", MessageBoxButton.OK, MessageBoxImage.Error);
        UpdateState();
    }

    private async void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        BtnStop.IsEnabled = false; BtnStart.IsEnabled = false;
        TxtRouting.Text = "Stopping routing…";
        await Task.Run(() => _c.StopRouting());   // off the UI thread: never freezes the window
        UpdateState();
    }

    private void BtnSettings_Click(object sender, RoutedEventArgs e)
    {
        new SettingsWindow(_c) { Owner = this }.ShowDialog();
        UpdateState();
    }

    private System.Windows.Forms.NotifyIcon CreateTrayIcon()
    {
        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Open App Proxy Manager", null, (_, _) => RestoreFromTray());
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitApplication());

        var icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!);
        var notifyIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = icon,
            Text = "App Proxy Manager",
            ContextMenuStrip = menu,
            Visible = true
        };
        notifyIcon.MouseClick += (_, e) =>
        {
            if (e.Button == System.Windows.Forms.MouseButtons.Left) RestoreFromTray();
        };
        return notifyIcon;
    }

    private void RestoreFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApplication()
    {
        _exitRequested = true;
        Close();
    }

    public void PrepareForApplicationShutdown() => _exitRequested = true;

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_exitRequested)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        if (_c.IsRouting)
        {
            var r = MessageBox.Show(this, "Routing is active. Closing the application stops routing and all traffic becomes direct again.\n\nClose anyway?",
                "App Proxy Manager", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (r != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                _exitRequested = false;
            }
        }

        if (!e.Cancel)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
    }

    // ---------------------------------------------------------------- live status

    private void UpdateState()
    {
        bool routing = _c.IsRouting;
        TxtRouting.Text = _c.RoutingSummary();
        RoutingDot.Fill = (Brush)FindResource(!routing ? "Muted" : (_c.ProxyUp ? "Good" : "Warn"));
        BtnStart.IsEnabled = !routing;
        BtnStop.IsEnabled = routing;
        TxtStats.Text = _c.StatsLine();
        TxtEmpty.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        if (TxtProxyStatus.Text is "" or "Proxy is reachable." or "Proxy is not reachable.")
            SetProxyStatus(_c.ProxyUp ? "Proxy is reachable." : "Proxy is not reachable.", (Brush)FindResource(_c.ProxyUp ? "Good" : "Bad"));

        foreach (var item in _items)
        {
            var rule = _c.Config.Apps.FirstOrDefault(a => string.Equals(a.Path, item.Path, StringComparison.OrdinalIgnoreCase));
            if (rule == null) continue;
            var (text, kind) = _c.StatusFor(rule);
            item.Status = text;
            item.StatusBrush = (Brush)FindResource(kind switch { StatusKind.Good => "Good", StatusKind.Warn => "Warn", StatusKind.Bad => "Bad", _ => "Muted" });
        }
    }
}
