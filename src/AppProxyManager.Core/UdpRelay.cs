using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace AppProxyManager.Core;

/// <summary>
/// Local UDP endpoint that WinDivert redirects selected datagrams to.
///  - DNS (UDP/53) is converted to DNS-over-TCP through the proxy (works with SOCKS5 and HTTP proxies, no leak).
///  - Other UDP uses SOCKS5 UDP ASSOCIATE (one association per client socket). Not available with HTTP proxies.
/// Replies are sent back to (remote IP, client port); the packet engine rewrites their source to the real remote port.
/// </summary>
public sealed class UdpRelay : IDisposable
{
    private readonly NatTable _nat;
    private readonly Func<ProxySettings> _proxy;
    private readonly Func<string> _dnsServer;
    private readonly ILog _log;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<ushort, Lazy<Task<Socks5UdpSession>>> _sessions = new();
    private Socket? _sock;
    public int Port { get; private set; }
    public long Datagrams, DnsQueries, Dropped;

    public UdpRelay(NatTable nat, Func<ProxySettings> proxy, Func<string> dnsServer, ILog? log = null)
    {
        _nat = nat; _proxy = proxy; _dnsServer = dnsServer; _log = log ?? NullLog.Instance;
    }

    public void Start()
    {
        _sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _sock.Bind(new IPEndPoint(IPAddress.Any, 0));
        Socks5UdpSession.DisableConnReset(_sock);
        Port = ((IPEndPoint)_sock.LocalEndPoint!).Port;
        _ = ReceiveLoop();
        _ = Janitor();
    }

    private async Task ReceiveLoop()
    {
        var buf = new byte[65535];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var r = await _sock!.ReceiveFromAsync(buf, SocketFlags.None, any, _cts.Token).ConfigureAwait(false);
                var from = (IPEndPoint)r.RemoteEndPoint;
                var payload = buf.AsSpan(0, r.ReceivedBytes).ToArray();
                if (!_nat.TryGet(new FlowKey((ushort)from.Port, IpUtil.ToUInt(from.Address)), out var e)) continue; // not ours
                _ = e.IsDns ? HandleDns(from, payload) : HandleUdp(from, e, payload);
            }
            catch (SocketException) { }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
        }
    }

    private async Task HandleDns(IPEndPoint from, byte[] query)
    {
        try
        {
            Interlocked.Increment(ref DnsQueries);
            var resolver = IPAddress.Parse(_dnsServer());
            var resp = await DnsOverTcp.QueryAsync(_proxy(), resolver, query, _cts.Token).ConfigureAwait(false);
            await _sock!.SendToAsync(resp, SocketFlags.None, from).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Interlocked.Increment(ref Dropped);
            _log.Warn("DNS via proxy failed: " + e.Message);  // no fallback to the local resolver on purpose
        }
    }

    private async Task HandleUdp(IPEndPoint from, NatEntry e, byte[] payload)
    {
        ushort clientPort = (ushort)from.Port;
        try
        {
            var lazy = _sessions.GetOrAdd(clientPort, _ => new Lazy<Task<Socks5UdpSession>>(() => CreateSession(clientPort, e)));
            Socks5UdpSession s;
            try { s = await lazy.Value.ConfigureAwait(false); }
            catch { _sessions.TryRemove(clientPort, out _); throw; }
            if (s.IsClosed) { _sessions.TryRemove(clientPort, out _); Interlocked.Increment(ref Dropped); return; }
            Interlocked.Increment(ref Datagrams);
            await s.SendToAsync(from.Address, e.OrigPort, payload).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref Dropped);
            _log.Warn("UDP via proxy failed: " + ex.Message);
        }
    }

    private async Task<Socks5UdpSession> CreateSession(ushort clientPort, NatEntry origin)
    {
        var s = await Socks5UdpSession.CreateAsync(_proxy(), _cts.Token).ConfigureAwait(false);
        s.OnDatagram = (src, port, data) =>
        {
            if (src.AddressFamily != AddressFamily.InterNetwork) return Task.CompletedTask; // v6 replies cannot be reflected
            // tell the packet engine which remote port this reply must appear to come from
            _nat.Set(new FlowKey(clientPort, IpUtil.ToUInt(src)),
                new NatEntry { LocalIp = origin.LocalIp, OrigPort = port, Pid = origin.Pid });
            return _sock!.SendToAsync(data, SocketFlags.None, new IPEndPoint(src, clientPort));
        };
        return s;
    }

    private async Task Janitor()
    {
        while (!_cts.IsCancellationRequested)
        {
            try { await Task.Delay(15_000, _cts.Token).ConfigureAwait(false); } catch { return; }
            foreach (var kv in _sessions)
            {
                if (!kv.Value.IsValueCreated || !kv.Value.Value.IsCompletedSuccessfully) continue;
                var s = kv.Value.Value.Result;
                if (s.IsClosed || Environment.TickCount64 - s.LastActivity > 120_000)
                {
                    s.Dispose();
                    _sessions.TryRemove(kv.Key, out _);
                }
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        foreach (var kv in _sessions)
            if (kv.Value.IsValueCreated && kv.Value.Value.IsCompletedSuccessfully) kv.Value.Value.Result.Dispose();
        try { _sock?.Dispose(); } catch { }
    }
}
