using System.Diagnostics;
using System.IO;
using AppProxyManager.Core;
using AppProxyManager.Engine;

namespace AppProxyManager.UI;

public sealed record StartOutcome(bool Ok, bool NeedsElevation, string? Error);
public sealed record AddResult(int Added, List<string> Duplicates, List<string> Rejected);

/// <summary>All application logic that is independent of WPF (so it can be reasoned about and compiled separately).</summary>
public sealed class AppController : IDisposable
{
    public FileLog Log { get; }
    public ConfigStore Store { get; }
    public AppConfig Config { get; private set; }
    public RoutingEngine Engine { get; }
    public ProxyMonitor Monitor { get; }
    public string? LastError { get; private set; }
    public event Action? StateChanged;

    public bool IsRouting => Engine.IsRunning;
    public bool ProxyUp => Monitor.IsUp;
    public bool IsElevated { get; } = Elevation.IsElevated();

    public AppController()
    {
        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppProxyManager", "logs");
        Log = new FileLog(Path.Combine(logDir, "app.log"));
        Store = new ConfigStore(new DpapiProtector());
        Config = Store.Load();
        Engine = new RoutingEngine(Log);
        Engine.Faulted += msg =>
        {
            LastError = "Routing stopped unexpectedly: " + msg;
            try { Engine.Stop(); } catch { }
            StateChanged?.Invoke();
        };
        Monitor = new ProxyMonitor(() => Config.Proxy);
        Monitor.StateChanged += up =>
        {
            Log.Info(up ? "Proxy is reachable." : "Proxy is NOT reachable" + (IsRouting ? " - routed applications are blocked until it returns (no direct fallback)." : "."));
            StateChanged?.Invoke();
        };
        Monitor.Start();
        Log.Info($"App Proxy Manager started (elevated: {IsElevated}).");
    }

    public void Save()
    {
        try { Store.Save(Config); }
        catch (Exception e) { Log.Error("Could not save settings", e); LastError = "Could not save settings: " + e.Message; }
    }

    /// <summary>Call after any change of proxy settings or the application list.</summary>
    public void ConfigChanged()
    {
        Save();
        if (IsRouting) Engine.UpdateConfig(Config);
        StateChanged?.Invoke();
    }

    public AddResult AddApps(IEnumerable<string> paths)
    {
        int added = 0; var dup = new List<string>(); var bad = new List<string>();
        string self = AppConfig.Normalize(Environment.ProcessPath ?? "");
        foreach (var raw in paths)
        {
            string p;
            try { p = AppConfig.Normalize(raw); } catch { bad.Add(raw); continue; }
            if (!p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(p)) { bad.Add(p); continue; }
            if (string.Equals(p, self, StringComparison.OrdinalIgnoreCase)) { bad.Add(p + " (this program cannot route itself)"); continue; }
            if (Config.AddApp(p)) added++; else dup.Add(p);
        }
        if (added > 0) ConfigChanged();
        return new AddResult(added, dup, bad);
    }

    public void RemoveApps(IEnumerable<string> paths)
    {
        bool any = false;
        foreach (var p in paths) any |= Config.RemoveApp(p);
        if (any) ConfigChanged();
    }

    public StartOutcome StartRouting()
    {
        LastError = null;
        if (!IsElevated) return new StartOutcome(false, true, null);
        try { Engine.Start(Config); }
        catch (EngineException e) { LastError = e.Message; Log.Error("Start failed: " + e.Message); StateChanged?.Invoke(); return new StartOutcome(false, false, e.Message); }
        catch (Exception e) { LastError = e.Message; Log.Error("Start failed", e); StateChanged?.Invoke(); return new StartOutcome(false, false, e.Message); }
        StateChanged?.Invoke();
        return new StartOutcome(true, false, null);
    }

    public void StopRouting()
    {
        try { Engine.Stop(); } catch (Exception e) { Log.Error("Stop failed", e); }
        StateChanged?.Invoke();
    }

    /// <summary>Human readable proxy status of one list entry.</summary>
    public (string Text, StatusKind Kind) StatusFor(AppRule r)
    {
        if (!r.Enabled) return ("Disabled", StatusKind.Neutral);
        if (!File.Exists(r.Path)) return ("File not found", StatusKind.Bad);
        if (!IsRouting) return ("Not routing", StatusKind.Neutral);
        if (!ProxyUp) return ("Blocked: proxy unreachable", StatusKind.Warn);
        if (Engine.GetActivity().TryGetValue(r.Path, out var a) && a.Flows > 0)
        {
            bool recent = Environment.TickCount64 - a.LastTicks < 15_000;
            return (recent ? $"Proxied · active ({a.Flows})" : $"Proxied ({a.Flows})", StatusKind.Good);
        }
        return IsProcessRunning(r.Path) ? ("Running · waiting for traffic", StatusKind.Good) : ("Ready · not running", StatusKind.Neutral);
    }

    private static bool IsProcessRunning(string path)
    {
        try
        {
            var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path));
            bool any = procs.Length > 0;
            foreach (var p in procs) p.Dispose();
            return any;
        }
        catch { return false; }
    }

    public string RoutingSummary()
    {
        var p = Config.Proxy;
        string proxy = $"{(p.Type == ProxyType.Socks5 ? "SOCKS5" : "HTTP")} {p.Host}:{p.Port}";
        if (!IsRouting)
            return LastError != null ? "Routing stopped: " + LastError : "Routing stopped. All applications use their normal direct connection.";
        int n = Config.Apps.Count(a => a.Enabled);
        return ProxyUp
            ? $"Routing ACTIVE: {n} application(s) via {proxy}"
            : $"Routing ACTIVE, but the proxy ({proxy}) is unreachable. Listed apps are blocked (never sent directly) until it returns.";
    }

    public string StatsLine() => IsRouting
        ? $"TCP flows: {Engine.ProxiedTcpFlows}   UDP datagrams: {Engine.ProxiedUdpDatagrams}   DNS queries: {Engine.ProxiedDnsQueries}   IPv6 dropped: {Engine.DroppedIPv6}"
        : (IsElevated ? "Administrator: yes" : "Administrator: no (requested when you start routing)");

    public void Dispose()
    {
        Monitor.Dispose();
        Engine.Dispose();
        Log.Info("App Proxy Manager exited.");
    }
}

public enum StatusKind { Neutral, Good, Warn, Bad }
