using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using AppProxyManager.Core;

namespace AppProxyManager.Engine;

public sealed class EngineException : Exception
{
    public EngineException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed class AppActivity
{
    public long Flows;
    public long LastTicks;
}

/// <summary>
/// Per-process transparent proxying built on WinDivert.
///
///  SOCKET layer (sniff only)   -> learns "local port -> process id" for every new TCP/UDP socket.
///  NETWORK layer (intercept)   -> outbound packets of routed processes are reflected to a local redirector
///                                 (TCP) or relay (UDP); replies are rewritten back so the app sees the real server.
///  TcpRedirector / UdpRelay    -> open the real connection through the SOCKS5/HTTP proxy.
///
/// Everything that does not belong to a routed process is re-injected untouched.
/// </summary>
public sealed class RoutingEngine : IDisposable
{
    private const byte Tcp = 6, Udp = 17;
    private readonly ILog _log;
    private volatile AppConfig _cfg = new();
    private readonly NatTable _tcpNat = new(), _udpNat = new();
    private readonly PidTable _pids = new(NativeMethods.FallbackPid);
    private readonly ConcurrentDictionary<string, AppActivity> _activity = new(StringComparer.OrdinalIgnoreCase);
    private RoutingPolicy _policy = new(NativeMethods.GetProcessPath);
    private TcpRedirector? _tcp;
    private UdpRelay? _udpRelay;
    private IntPtr _sockH = WinDivertNative.InvalidHandle, _netH = WinDivertNative.InvalidHandle;
    private Thread? _sockThread, _netThread, _maintThread;
    private volatile bool _running;
    private int _dnsPid;
    private readonly object _gate = new();

    public bool IsRunning => _running;
    private PacketTranslator? _translator;
    public long ProxiedTcpFlows => _translator?.ProxiedTcpFlows ?? 0;
    public long ProxiedUdpDatagrams => _translator?.ProxiedUdpDatagrams ?? 0;
    public long ProxiedDnsQueries => _translator?.ProxiedDnsQueries ?? 0;
    public long DroppedIPv6 => _translator?.DroppedIPv6 ?? 0;
    public long DroppedUdp => _translator?.DroppedUdp ?? 0;
    public int ExistingConnectionsReset { get; private set; }
    public event Action<string>? Faulted;

    public RoutingEngine(ILog? log = null) { _log = log ?? NullLog.Instance; }

    public IReadOnlyDictionary<string, AppActivity> GetActivity() => _activity;

    // ------------------------------------------------------------------ lifecycle

    public void Start(AppConfig cfg)
    {
        lock (_gate)
        {
            if (_running) return;
            if (!Elevation.IsElevated())
                throw new EngineException("Administrator rights are required to load the WinDivert network driver.");
            string dir = AppContext.BaseDirectory;
            if (!File.Exists(Path.Combine(dir, "WinDivert.dll")) || !File.Exists(Path.Combine(dir, "WinDivert64.sys")))
                throw new EngineException("WinDivert.dll / WinDivert64.sys are missing next to the application. Reinstall the application with its required files.");
            if (!Environment.Is64BitProcess)
                throw new EngineException("A 64-bit process is required (WinDivert64.sys).");

            _cfg = cfg;
            _policy = new RoutingPolicy(NativeMethods.GetProcessPath);
            RefreshRules();
            try
            {
                FirewallRule.Ensure(Environment.ProcessPath!);
                _tcp = new TcpRedirector(_tcpNat, () => _cfg.Proxy, _log); _tcp.Start();
                _udpRelay = new UdpRelay(_udpNat, () => _cfg.Proxy, () => _cfg.DnsServer, _log); _udpRelay.Start();
                _dnsPid = cfg.RouteSystemDns ? NativeMethods.GetServicePid("Dnscache") : 0;
                _translator = new PacketTranslator(_tcpNat, _udpNat, _pids, _policy, () => _cfg,
                    () => _tcp?.Port ?? 0, () => _udpRelay?.Port ?? 0, () => _dnsPid, Record);

                _sockH = Open("true", WinDivertLayer.Socket, 0, WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);
                _netH = Open("outbound and !loopback and (tcp or udp)", WinDivertLayer.Network, 0, WinDivertFlags.None);
            }
            catch
            {
                StopInternal();
                throw;
            }
            _running = true;
            _sockThread = new Thread(SocketLoop) { IsBackground = true, Name = "apm-socket-events" };
            _netThread = new Thread(NetworkLoop) { IsBackground = true, Name = "apm-packets", Priority = ThreadPriority.AboveNormal };
            _maintThread = new Thread(MaintenanceLoop) { IsBackground = true, Name = "apm-maintenance" };
            _sockThread.Start(); _netThread.Start(); _maintThread.Start();

            if (cfg.ResetExistingConnections)
            {
                ExistingConnectionsReset = NativeMethods.ResetTcpConnections(pid => _policy.IsRouted(pid, out _), cfg.BypassLan);
                if (ExistingConnectionsReset > 0) _log.Info($"Reset {ExistingConnectionsReset} existing connection(s) so they reconnect through the proxy.");
            }
            _log.Info($"Routing started: {cfg.Apps.Count(a => a.Enabled)} application(s) via {cfg.Proxy.Type} {cfg.Proxy.Host}:{cfg.Proxy.Port}. " +
                      $"TCP redirector port {_tcp!.Port}, UDP relay port {_udpRelay!.Port}.");
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (!_running && _sockH == WinDivertNative.InvalidHandle && _netH == WinDivertNative.InvalidHandle) return;
            StopInternal();
            _log.Info("Routing stopped. All traffic is direct again.");
        }
    }

    private void StopInternal()
    {
        _running = false;
        var net = _netH; var sock = _sockH;
        _netH = WinDivertNative.InvalidHandle; _sockH = WinDivertNative.InvalidHandle;
        // 1) Shutdown aborts the blocking Recv calls immediately; 2) reader threads exit; 3) only then Close.
        //    The network handle goes first: once it is shut down, traffic flows directly again.
        if (net != WinDivertNative.InvalidHandle) WinDivertNative.WinDivertShutdown(net, 3);
        if (sock != WinDivertNative.InvalidHandle) WinDivertNative.WinDivertShutdown(sock, 3);
        foreach (var t in new[] { _netThread, _sockThread, _maintThread })
            if (t != null && t.IsAlive && t != Thread.CurrentThread) t.Join(2000);
        _netThread = _sockThread = _maintThread = null;
        if (net != WinDivertNative.InvalidHandle) WinDivertNative.WinDivertClose(net);
        if (sock != WinDivertNative.InvalidHandle) WinDivertNative.WinDivertClose(sock);
        _tcp?.Dispose(); _tcp = null;
        _udpRelay?.Dispose(); _udpRelay = null;
        _tcpNat.Prune(0); _udpNat.Prune(0);
        _activity.Clear();
    }

    /// <summary>Applies a changed application list / settings while routing is running (new connections only).</summary>
    public void UpdateConfig(AppConfig cfg)
    {
        _cfg = cfg;
        if (_running) RefreshRules();
    }

    public void Dispose() => Stop();

    private static IntPtr Open(string filter, WinDivertLayer layer, short priority, WinDivertFlags flags)
    {
        IntPtr h = WinDivertNative.WinDivertOpen(filter, (int)layer, priority, (ulong)flags);
        if (h == WinDivertNative.InvalidHandle)
            throw new EngineException(Describe(Marshal.GetLastWin32Error()));
        return h;
    }

    private static string Describe(int err) => err switch
    {
        5 => "Access denied while opening the WinDivert driver. Start the application as Administrator.",
        2 => "WinDivert64.sys was not found next to the application.",
        87 => "WinDivert rejected its filter (invalid parameter). This is a bug; please report it with the log file.",
        577 => "Windows refused to load the WinDivert driver because its signature could not be verified (error 577). " +
               "Keep Windows up to date, and see the Troubleshooting section about Secure Boot / driver signing.",
        1275 => "Windows blocked the WinDivert driver (error 1275): Smart App Control, Memory Integrity (HVCI) or the vulnerable-driver " +
                "blocklist prevented loading it. See the Troubleshooting section of the README.",
        1058 or 1060 => "The WinDivert driver service is disabled or damaged. Run scripts\\uninstall-driver.bat and try again.",
        1753 => "The Windows 'Base Filtering Engine' service is not running (error 1753). Start it in services.msc and try again.",
        1393 => "The WinDivert driver is in use by another program or damaged (error 1393). Reboot, or run scripts\\uninstall-driver.bat.",
        _ => $"Could not open the WinDivert driver (Win32 error {err})."
    };

    // ------------------------------------------------------------------ rules

    private void RefreshRules()
    {
        var cfg = _cfg;
        var routed = cfg.Apps.Where(a => a.Enabled).Select(a => a.Path).ToList();
        var excluded = new List<string> { Environment.ProcessPath! };   // never route ourselves
        if (IsLocalHost(cfg.Proxy.Host))
        {
            // never route the program that provides the proxy (Hiddify / sing-box / xray ...): that would create a loop
            int pid = NativeMethods.GetTcpListenerPid(cfg.Proxy.Port);
            var path = pid > 0 ? NativeMethods.GetProcessPath(pid) : null;
            if (path != null)
            {
                excluded.Add(path);
                if (routed.Any(r => string.Equals(r, path, StringComparison.OrdinalIgnoreCase)))
                    _log.Warn($"'{Path.GetFileName(path)}' provides the proxy itself and is NOT routed (it would loop back into the proxy).");
            }
        }
        _policy.SetRules(routed, excluded);
    }

    private static bool IsLocalHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(host, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        try { return Dns.GetHostAddresses(Dns.GetHostName()).Any(a => a.Equals(ip)); } catch { return false; }
    }

    // ------------------------------------------------------------------ socket events (pid mapping)

    private void SocketLoop()
    {
        var addr = new WinDivertAddress();
        IntPtr h = _sockH;
        while (_running)
        {
            if (!WinDivertNative.WinDivertRecvEvent(h, IntPtr.Zero, 0, IntPtr.Zero, ref addr))
            {
                if (!_running) break;
                int e = Marshal.GetLastWin32Error();
                if (e is 1 or 6 or 232 or 995) break;   // handle closed / shut down / I/O aborted
                Thread.Sleep(1);
                continue;
            }
            byte ev = addr.Event, proto = addr.Protocol;
            if (proto != Tcp && proto != Udp) continue;
            if (ev == WinDivertNative.EventSocketListen) continue;
            _pids.Observe(proto, addr.LocalPort, (int)addr.ProcessId, ev == WinDivertNative.EventSocketClose);
        }
    }

    // ------------------------------------------------------------------ packet path

    private void NetworkLoop()
    {
        var buf = new byte[65535];
        var addr = new WinDivertAddress();
        IntPtr h = _netH;
        int errors = 0;
        try
        {
            while (_running)
            {
                if (!WinDivertNative.WinDivertRecv(h, buf, (uint)buf.Length, out uint len, ref addr))
                {
                    if (!_running) break;
                    int e = Marshal.GetLastWin32Error();
                    if (e is 1 or 6 or 232 or 995) break;
                    if (++errors > 200) throw new EngineException($"WinDivert receive keeps failing (Win32 error {e}).");
                    Thread.Sleep(1);
                    continue;
                }
                errors = 0;
                Verdict v;
                try { v = _translator!.Translate(buf, (int)len); }
                catch (Exception ex) { _log.Error("Packet handling error (packet passed through unchanged)", ex); v = Verdict.Pass; }
                if (v == Verdict.Drop) continue;
                if (v == Verdict.ReinjectInbound) addr.Outbound = false;   // reflect to the local redirector / back to the application
                WinDivertNative.WinDivertSend(h, buf, len, out _, ref addr);
            }
        }
        catch (Exception ex)
        {
            if (_running) { _log.Error("Packet engine stopped unexpectedly", ex); Faulted?.Invoke(ex.Message); }
        }
        finally
        {
            // fail open: never leave the network handle open without a reader (that would black-hole all traffic)
            if (_running) { _running = false; try { WinDivertNative.WinDivertShutdown(h, 3); WinDivertNative.WinDivertClose(h); } catch { } _netH = WinDivertNative.InvalidHandle; }
        }
    }

    private void Record(string? path)
    {
        if (path == null) return;
        var a = _activity.GetOrAdd(path, _ => new AppActivity());
        Interlocked.Increment(ref a.Flows);
        a.LastTicks = Environment.TickCount64;
    }

    // ------------------------------------------------------------------ housekeeping

    private void MaintenanceLoop()
    {
        int tick = 0;
        while (_running)
        {
            for (int i = 0; i < 50 && _running; i++) Thread.Sleep(100);   // 5 s
            if (!_running) break;
            try
            {
                _tcpNat.Prune(15 * 60_000);
                _udpNat.Prune(2 * 60_000);
                _pids.Prune();
                if (++tick % 2 == 0)
                {
                    RefreshRules();   // picks up a restarted proxy program / pid reuse
                    if (_cfg.RouteSystemDns) _dnsPid = NativeMethods.GetServicePid("Dnscache");
                }
            }
            catch (Exception ex) { _log.Error("Maintenance error", ex); }
        }
    }
}
