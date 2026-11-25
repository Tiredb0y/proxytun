using System.Diagnostics;
using System.Net;
using System.Windows;
using AppProxyManager.Engine;

namespace AppProxyManager.UI;

public partial class SettingsWindow : Window
{
    private readonly AppController _c;

    public SettingsWindow(AppController c)
    {
        InitializeComponent();
        _c = c;
        var cfg = c.Config;
        ChkLogon.IsChecked = StartupTask.IsEnabled();
        ChkMinimized.IsChecked = cfg.StartMinimized;
        ChkAutoStart.IsChecked = cfg.AutoStartRouting;
        ChkLan.IsChecked = cfg.BypassLan;
        ChkV6.IsChecked = cfg.BlockIPv6ForRoutedApps;
        ChkReset.IsChecked = cfg.ResetExistingConnections;
        ChkSysDns.IsChecked = cfg.RouteSystemDns;
        TxtDns.Text = cfg.DnsServer;
    }

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        if (!IPAddress.TryParse(TxtDns.Text.Trim(), out var dns) || dns.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            MessageBox.Show(this, "Enter the DNS server as an IPv4 address, for example 1.1.1.1.", "Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var cfg = _c.Config;
        cfg.DnsServer = dns.ToString();
        cfg.StartMinimized = ChkMinimized.IsChecked == true;
        cfg.AutoStartRouting = ChkAutoStart.IsChecked == true;
        cfg.BypassLan = ChkLan.IsChecked == true;
        cfg.BlockIPv6ForRoutedApps = ChkV6.IsChecked == true;
        cfg.ResetExistingConnections = ChkReset.IsChecked == true;
        cfg.RouteSystemDns = ChkSysDns.IsChecked == true;

        bool wantLogon = ChkLogon.IsChecked == true;
        if (wantLogon != StartupTask.IsEnabled())
        {
            if (!StartupTask.Set(wantLogon))
                MessageBox.Show(this, "The sign-in task could not be changed (the administrator prompt was declined or failed).", "Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
            else cfg.LaunchAtLogon = wantLogon;
        }
        _c.ConfigChanged();
        if (_c.IsRouting)
            MessageBox.Show(this, "Saved. Stop and start routing to apply DNS-related changes (system DNS, IPv6, reset).", "Settings", MessageBoxButton.OK, MessageBoxImage.Information);
        Close();
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();

    private void BtnLogs_Click(object sender, RoutedEventArgs e) =>
        Open(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppProxyManager", "logs"));

    private void BtnData_Click(object sender, RoutedEventArgs e) => Open(Core.ConfigStore.DefaultDirectory);

    private static void Open(string dir)
    {
        System.IO.Directory.CreateDirectory(dir);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
    }
}
