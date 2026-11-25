using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AppProxyManager.Core;

public sealed class ProxyException : IOException
{
    public ProxyException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Opens TCP tunnels through a SOCKS5 or HTTP(CONNECT) proxy.</summary>
public static class ProxyDialer
{
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);

    public static Task<Socket> ConnectTcpAsync(ProxySettings p, IPAddress target, int port, CancellationToken ct) =>
        ConnectCoreAsync(p, null, target, port, ct);

    public static Task<Socket> ConnectTcpAsync(ProxySettings p, string host, int port, CancellationToken ct) =>
        IPAddress.TryParse(host, out var ip) ? ConnectCoreAsync(p, null, ip, port, ct) : ConnectCoreAsync(p, host, null, port, ct);

    private static async Task<Socket> ConnectCoreAsync(ProxySettings p, string? host, IPAddress? ip, int port, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(HandshakeTimeout);
        Socket s = await ConnectToProxyAsync(p, cts.Token).ConfigureAwait(false);
        try
        {
            if (p.Type == ProxyType.Socks5)
            {
                await Socks5HandshakeAsync(s, p, cts.Token).ConfigureAwait(false);
                await Socks5CommandAsync(s, 0x01, host, ip, port, cts.Token).ConfigureAwait(false);
            }
            else
            {
                await HttpConnectAsync(s, p, host ?? ip!.ToString(), port, cts.Token).ConfigureAwait(false);
            }
            return s;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            s.Dispose();
            throw new ProxyException("Timed out while talking to the proxy.");
        }
        catch { s.Dispose(); throw; }
    }

    public static async Task<Socket> ConnectToProxyAsync(ProxySettings p, CancellationToken ct)
    {
        IPAddress[] addrs = IPAddress.TryParse(p.Host, out var parsed)
            ? new[] { parsed }
            : await Dns.GetHostAddressesAsync(p.Host, ct).ConfigureAwait(false);
        Exception? last = null;
        foreach (var a in addrs)
        {
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(HandshakeTimeout);
                await s.ConnectAsync(new IPEndPoint(a, p.Port), cts.Token).ConfigureAwait(false);
                return s;
            }
            catch (Exception e)
            {
                s.Dispose();
                last = e;
                if (ct.IsCancellationRequested) throw;
            }
        }
        throw new ProxyException($"Cannot connect to proxy {p.Host}:{p.Port} ({last?.Message ?? "no address"}).", last);
    }

    // ---------------- SOCKS5 (RFC 1928 / 1929) ----------------

    public static async Task Socks5HandshakeAsync(Socket s, ProxySettings p, CancellationToken ct)
    {
        byte[] hello = p.HasCredentials ? new byte[] { 5, 2, 0x00, 0x02 } : new byte[] { 5, 1, 0x00 };
        await s.SendAsync(hello, SocketFlags.None, ct).ConfigureAwait(false);
        var r = new byte[2];
        await ReadExactAsync(s, r, 2, ct).ConfigureAwait(false);
        if (r[0] != 5) throw new ProxyException("The configured port is not a SOCKS5 server (bad version in reply).");
        switch (r[1])
        {
            case 0x00: return;
            case 0x02:
                if (!p.HasCredentials) throw new ProxyException("The proxy requires a username and password.");
                var u = Encoding.UTF8.GetBytes(p.Username!);
                var pw = Encoding.UTF8.GetBytes(p.Password ?? "");
                if (u.Length > 255 || pw.Length > 255) throw new ProxyException("Username/password too long for SOCKS5.");
                var req = new byte[3 + u.Length + pw.Length];
                req[0] = 1; req[1] = (byte)u.Length; u.CopyTo(req, 2);
                req[2 + u.Length] = (byte)pw.Length; pw.CopyTo(req, 3 + u.Length);
                await s.SendAsync(req, SocketFlags.None, ct).ConfigureAwait(false);
                await ReadExactAsync(s, r, 2, ct).ConfigureAwait(false);
                if (r[1] != 0) throw new ProxyException("The proxy rejected the username/password.");
                return;
            case 0xFF:
                throw new ProxyException(p.HasCredentials
                    ? "The proxy accepts none of the offered authentication methods."
                    : "The proxy does not allow anonymous access: enter a username and password.");
            default:
                throw new ProxyException($"Unsupported SOCKS5 authentication method 0x{r[1]:X2}.");
        }
    }

    /// <summary>Sends a SOCKS5 command (1=CONNECT, 3=UDP ASSOCIATE) and returns the bound address/port.</summary>
    public static async Task<(IPAddress? Addr, ushort Port)> Socks5CommandAsync(
        Socket s, byte cmd, string? host, IPAddress? ip, int port, CancellationToken ct)
    {
        var req = new List<byte> { 5, cmd, 0 };
        if (ip != null)
        {
            var b = ip.GetAddressBytes();
            req.Add(b.Length == 4 ? (byte)1 : (byte)4);
            req.AddRange(b);
        }
        else
        {
            var h = Encoding.ASCII.GetBytes(host ?? "");
            if (h.Length == 0 || h.Length > 255) throw new ProxyException("Invalid target host name.");
            req.Add(3); req.Add((byte)h.Length); req.AddRange(h);
        }
        req.Add((byte)(port >> 8)); req.Add((byte)port);
        await s.SendAsync(req.ToArray(), SocketFlags.None, ct).ConfigureAwait(false);

        var hdr = new byte[4];
        await ReadExactAsync(s, hdr, 4, ct).ConfigureAwait(false);
        if (hdr[0] != 5) throw new ProxyException("Invalid SOCKS5 reply.");
        if (hdr[1] != 0) throw new ProxyException("SOCKS5 request failed: " + ReplyText(hdr[1]));
        IPAddress? bound = null;
        switch (hdr[3])
        {
            case 1: { var a = new byte[4]; await ReadExactAsync(s, a, 4, ct).ConfigureAwait(false); bound = new IPAddress(a); break; }
            case 4: { var a = new byte[16]; await ReadExactAsync(s, a, 16, ct).ConfigureAwait(false); bound = new IPAddress(a); break; }
            case 3: { var l = new byte[1]; await ReadExactAsync(s, l, 1, ct).ConfigureAwait(false); await ReadExactAsync(s, new byte[l[0]], l[0], ct).ConfigureAwait(false); break; }
            default: throw new ProxyException("Invalid address type in SOCKS5 reply.");
        }
        var pb = new byte[2];
        await ReadExactAsync(s, pb, 2, ct).ConfigureAwait(false);
        return (bound, (ushort)((pb[0] << 8) | pb[1]));
    }

    private static string ReplyText(byte code) => code switch
    {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused by target",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => $"code {code}"
    };

    // ---------------- HTTP CONNECT ----------------

    private static async Task HttpConnectAsync(Socket s, ProxySettings p, string host, int port, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append($"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if (p.HasCredentials)
            sb.Append("Proxy-Authorization: Basic ").Append(Convert.ToBase64String(Encoding.UTF8.GetBytes($"{p.Username}:{p.Password}"))).Append("\r\n");
        sb.Append("\r\n");
        await s.SendAsync(Encoding.ASCII.GetBytes(sb.ToString()), SocketFlags.None, ct).ConfigureAwait(false);

        // read response headers one byte at a time so no tunnel data is consumed
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            await ReadExactAsync(s, one, 1, ct).ConfigureAwait(false);
            head.Append((char)one[0]);
            if (head.Length > 16384) throw new ProxyException("HTTP proxy response too large.");
        }
        var status = head.ToString().Split("\r\n")[0];
        var parts = status.Split(' ', 3);
        if (parts.Length < 2 || parts[1] != "200")
            throw new ProxyException("HTTP proxy refused CONNECT: " + status);
    }

    public static async Task ReadExactAsync(Socket s, byte[] buf, int count, CancellationToken ct)
    {
        int o = 0;
        while (o < count)
        {
            int n = await s.ReceiveAsync(buf.AsMemory(o, count - o), SocketFlags.None, ct).ConfigureAwait(false);
            if (n == 0) throw new ProxyException("The proxy closed the connection during the handshake.");
            o += n;
        }
    }
}
