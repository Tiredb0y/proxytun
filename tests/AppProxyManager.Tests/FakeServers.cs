using System.Net;
using System.Net.Sockets;
using System.Text;
using AppProxyManager.Core;

namespace AppProxyManager.Tests;

/// <summary>A small but real SOCKS5 server (CONNECT + UDP ASSOCIATE + user/pass) used as the "Hiddify" stand-in.</summary>
public sealed class FakeSocks5 : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
    public string? User, Pass;
    public readonly List<string> Requests = new();
    public int UdpAssociations;
    private readonly CancellationTokenSource _cts = new();

    public FakeSocks5() { _l.Start(); _ = Accept(); }

    private async Task Accept()
    {
        while (!_cts.IsCancellationRequested)
        {
            Socket c;
            try { c = await _l.AcceptSocketAsync(_cts.Token); } catch { return; }
            _ = Task.Run(() => Handle(c));
        }
    }

    private static async Task<byte[]> Read(Socket s, int n)
    {
        var b = new byte[n]; int o = 0;
        while (o < n) { int r = await s.ReceiveAsync(b.AsMemory(o, n - o), SocketFlags.None); if (r == 0) throw new IOException("eof"); o += r; }
        return b;
    }

    private async Task Handle(Socket c)
    {
        try
        {
            var h = await Read(c, 2);
            var methods = await Read(c, h[1]);
            if (User != null)
            {
                if (!methods.Contains((byte)2)) { await c.SendAsync(new byte[] { 5, 0xFF }); return; }
                await c.SendAsync(new byte[] { 5, 2 });
                var v = await Read(c, 2);
                var u = Encoding.UTF8.GetString(await Read(c, v[1]));
                var pl = await Read(c, 1);
                var p = Encoding.UTF8.GetString(await Read(c, pl[0]));
                bool ok = u == User && p == Pass;
                await c.SendAsync(new byte[] { 1, (byte)(ok ? 0 : 1) });
                if (!ok) return;
            }
            else await c.SendAsync(new byte[] { 5, 0 });

            var req = await Read(c, 4);
            string host; 
            if (req[3] == 1) host = new IPAddress(await Read(c, 4)).ToString();
            else { var l = await Read(c, 1); host = Encoding.ASCII.GetString(await Read(c, l[0])); }
            var pb = await Read(c, 2);
            int port = (pb[0] << 8) | pb[1];

            if (req[1] == 1)
            {
                lock (Requests) Requests.Add($"{host}:{port}");
                var up = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try { await up.ConnectAsync(host == "localhost" ? "127.0.0.1" : host, port); }
                catch { await c.SendAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }); return; }
                await c.SendAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
                await Task.WhenAll(Pipe(c, up), Pipe(up, c));
            }
            else if (req[1] == 3)
            {
                Interlocked.Increment(ref UdpAssociations);
                var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                int up = ((IPEndPoint)udp.LocalEndPoint!).Port;
                await c.SendAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, (byte)(up >> 8), (byte)up });
                _ = UdpLoop(udp, c);
                var junk = new byte[1];
                while (await c.ReceiveAsync(junk, SocketFlags.None) > 0) { }
                udp.Dispose();
            }
        }
        catch { }
        finally { c.Dispose(); }
    }

    private static async Task UdpLoop(Socket udp, Socket control)
    {
        var buf = new byte[65535];
        EndPoint any = new IPEndPoint(IPAddress.Any, 0);
        IPEndPoint? client = null;
        var targets = new HashSet<IPEndPoint>();
        try
        {
            while (true)
            {
                var r = await udp.ReceiveFromAsync(buf, SocketFlags.None, any);
                var from = (IPEndPoint)r.RemoteEndPoint;
                if (client == null) client = from;
                if (from.Equals(client))
                {
                    if (!Socks5UdpCodec.TryDecode(buf.AsSpan(0, r.ReceivedBytes), out var a, out var port, out var off)) continue;
                    var dst = new IPEndPoint(a!, port);
                    targets.Add(dst);
                    await udp.SendToAsync(buf.AsMemory(off, r.ReceivedBytes - off), SocketFlags.None, dst);
                }
                else
                {
                    var wrapped = Socks5UdpCodec.Encode(from.Address, (ushort)from.Port, buf.AsSpan(0, r.ReceivedBytes));
                    await udp.SendToAsync(wrapped, SocketFlags.None, client);
                }
            }
        }
        catch { }
    }

    private static async Task Pipe(Socket a, Socket b)
    {
        var buf = new byte[16384];
        try
        {
            int n;
            while ((n = await a.ReceiveAsync(buf, SocketFlags.None)) > 0) await b.SendAsync(buf.AsMemory(0, n), SocketFlags.None);
            b.Shutdown(SocketShutdown.Send);
        }
        catch { }
    }

    public void Dispose() { _cts.Cancel(); _l.Stop(); }
}

/// <summary>HTTP CONNECT proxy stand-in.</summary>
public sealed class FakeHttpProxy : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
    public readonly List<string> Requests = new();
    public string? RequireAuth;

    public FakeHttpProxy() { _l.Start(); _ = Accept(); }

    private async Task Accept()
    {
        while (true)
        {
            Socket c;
            try { c = await _l.AcceptSocketAsync(); } catch { return; }
            _ = Task.Run(async () =>
            {
                try
                {
                    var sb = new StringBuilder(); var one = new byte[1];
                    while (!sb.ToString().EndsWith("\r\n\r\n")) { if (await c.ReceiveAsync(one, SocketFlags.None) == 0) return; sb.Append((char)one[0]); }
                    var text = sb.ToString();
                    var first = text.Split("\r\n")[0].Split(' ');
                    lock (Requests) Requests.Add(first[1]);
                    if (RequireAuth != null && !text.Contains("Proxy-Authorization: Basic " + RequireAuth))
                    { await c.SendAsync(Encoding.ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")); return; }
                    var hp = first[1].Split(':');
                    var up = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    await up.ConnectAsync(hp[0], int.Parse(hp[1]));
                    await c.SendAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\n\r\n"));
                    var a = Task.Run(async () => { var b = new byte[8192]; int n; try { while ((n = await c.ReceiveAsync(b, SocketFlags.None)) > 0) await up.SendAsync(b.AsMemory(0, n), SocketFlags.None); up.Shutdown(SocketShutdown.Send); } catch { } });
                    var d = Task.Run(async () => { var b = new byte[8192]; int n; try { while ((n = await up.ReceiveAsync(b, SocketFlags.None)) > 0) await c.SendAsync(b.AsMemory(0, n), SocketFlags.None); c.Shutdown(SocketShutdown.Send); } catch { } });
                    await Task.WhenAll(a, d);
                }
                catch { }
                finally { c.Dispose(); }
            });
        }
    }

    public void Dispose() => _l.Stop();
}

public sealed class EchoTcpServer : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
    public EchoTcpServer(Func<byte[], byte[]>? transform = null)
    {
        _l.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                Socket c;
                try { c = await _l.AcceptSocketAsync(); } catch { return; }
                _ = Task.Run(async () =>
                {
                    var b = new byte[4096]; int n;
                    try { while ((n = await c.ReceiveAsync(b, SocketFlags.None)) > 0) await c.SendAsync((transform?.Invoke(b[..n]) ?? b[..n]), SocketFlags.None); } catch { }
                    c.Dispose();
                });
            }
        });
    }
    public void Dispose() => _l.Stop();
}

public sealed class EchoUdpServer : IDisposable
{
    private readonly Socket _s = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    public int Port => ((IPEndPoint)_s.LocalEndPoint!).Port;
    public EchoUdpServer()
    {
        _s.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _ = Task.Run(async () =>
        {
            var b = new byte[2048]; EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            try { while (true) { var r = await _s.ReceiveFromAsync(b, SocketFlags.None, any); await _s.SendToAsync(b.AsMemory(0, r.ReceivedBytes), SocketFlags.None, r.RemoteEndPoint); } } catch { }
        });
    }
    public void Dispose() => _s.Dispose();
}

public sealed class FakeProtector : ISecretProtector
{
    public string Protect(string s) => "ENC:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(new string(s.Reverse().ToArray())));
    public string? Unprotect(string s) => s.StartsWith("ENC:") ? new string(Encoding.UTF8.GetString(Convert.FromBase64String(s[4..])).Reverse().ToArray()) : null;
}
