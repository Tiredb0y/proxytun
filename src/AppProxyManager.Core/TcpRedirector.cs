using System.Buffers;
using System.Net;
using System.Net.Sockets;

namespace AppProxyManager.Core;

/// <summary>
/// Local TCP endpoint that WinDivert redirects selected flows to. For each accepted connection the original
/// destination is recovered from the NAT table and a tunnel to that destination is opened through the proxy.
/// Connections that have no NAT entry are closed immediately (so the listener is useless to anyone else).
/// </summary>
public sealed class TcpRedirector : IDisposable
{
    private readonly NatTable _nat;
    private readonly Func<ProxySettings> _proxy;
    private readonly ILog _log;
    private readonly CancellationTokenSource _cts = new();
    private TcpListener? _listener;
    public int Port { get; private set; }
    public long Accepted, Failed;

    public TcpRedirector(NatTable nat, Func<ProxySettings> proxy, ILog? log = null)
    {
        _nat = nat; _proxy = proxy; _log = log ?? NullLog.Instance;
    }

    public void Start()
    {
        _listener = new TcpListener(IPAddress.Any, 0);
        _listener.Start(512);
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _ = AcceptLoop();
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket client;
            try { client = await _listener!.AcceptSocketAsync(_cts.Token).ConfigureAwait(false); }
            catch { return; }
            _ = Handle(client);
        }
    }

    private async Task Handle(Socket client)
    {
        NatEntry? entry = null;
        Socket? upstream = null;
        try
        {
            client.NoDelay = true;
            var remote = (IPEndPoint)client.RemoteEndPoint!;
            // the reflected packet carries (original destination IP, client source port) as its source
            if (!_nat.TryGet(new FlowKey((ushort)remote.Port, IpUtil.ToUInt(remote.Address)), out entry))
            { client.Dispose(); return; }
            Interlocked.Increment(ref Accepted);
            upstream = await ProxyDialer.ConnectTcpAsync(_proxy(), remote.Address, entry.OrigPort, _cts.Token).ConfigureAwait(false);
            await Task.WhenAll(Pump(client, upstream), Pump(upstream, client)).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Interlocked.Increment(ref Failed);
            _log.Warn($"TCP tunnel failed: {e.Message}");   // fail closed: the client connection is dropped, never sent directly
        }
        finally
        {
            entry?.MarkClosed();
            try { client.Dispose(); } catch { }
            try { upstream?.Dispose(); } catch { }
        }
    }

    private static async Task Pump(Socket from, Socket to)
    {
        var buf = ArrayPool<byte>.Shared.Rent(65536);
        try
        {
            while (true)
            {
                int n = await from.ReceiveAsync(buf.AsMemory(), SocketFlags.None).ConfigureAwait(false);
                if (n == 0) break;
                for (int o = 0; o < n;) o += await to.SendAsync(buf.AsMemory(o, n - o), SocketFlags.None).ConfigureAwait(false);
            }
            try { to.Shutdown(SocketShutdown.Send); } catch { }
        }
        catch
        {
            try { from.Dispose(); } catch { }
            try { to.Dispose(); } catch { }
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener?.Stop(); } catch { }
    }
}
