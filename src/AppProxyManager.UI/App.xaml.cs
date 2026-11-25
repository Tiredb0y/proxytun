using System.Windows;
using AppProxyManager.Engine;

namespace AppProxyManager.UI;

public partial class App : Application
{
    private Mutex? _mutex;
    private AppController? _controller;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += (_, a) =>
        {
            _controller?.Log.Error("Unhandled UI exception", a.Exception);
            MessageBox.Show("Unexpected error: " + a.Exception.Message + "\n\nDetails were written to the log file (Settings > Open log folder).",
                "App Proxy Manager", MessageBoxButton.OK, MessageBoxImage.Error);
            a.Handled = true;
        };

        // single instance (a freshly elevated copy waits briefly for the old, exiting one)
        for (int i = 0; i < 20 && !TryAcquireMutex(); i++) Thread.Sleep(250);
        if (_mutex == null)
        {
            MessageBox.Show("App Proxy Manager is already running.", "App Proxy Manager", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        bool startup = e.Args.Contains("--startup");
        bool explicitStart = e.Args.Contains("--start");
        _controller = new AppController();
        var win = new MainWindow(_controller);
        MainWindow = win;
        if (startup && _controller.Config.StartMinimized) win.WindowState = WindowState.Minimized;
        win.Show();
        if (explicitStart || (startup && _controller.Config.AutoStartRouting))
            win.StartRoutingFromCommandLine(silent: startup);
    }

    private bool TryAcquireMutex()
    {
        var m = new Mutex(true, "Local\\AppProxyManager.SingleInstance", out bool created);
        if (created) { _mutex = m; return true; }
        m.Dispose();
        return false;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _controller?.Dispose();
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        base.OnExit(e);
    }
}
