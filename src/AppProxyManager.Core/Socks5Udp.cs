using System.Net;
using System.Net.Sockets;

namespace AppProxyManager.Core;

public static class Socks5UdpCodec
{
    /// <summary>RSV(2) FRAG(1) ATYP ADDR PORT DATA for an IPv4 or IPv6 destination.</summary>
    public static byte[] Encode(IPAddress dst, ushort port, ReadOnlySpan<byte> payload)
    {
        var a = dst.GetAddressBytes();
        var buf = new byte[4 + a.Length + 2 + payload.Length];
        buf[3] = a.Length == 4 ? (byte)1 : (byte)4;
        a.CopyTo(buf, 4);
        buf[4 + a.Length] = (byte)(port >> 8);
        buf[5 + a.Length] = (byte)port;
        payload.CopyTo(buf.AsSpan(6 + a.Length));
        return buf;
    }

    /// <summary>Returns false for fragments, domain names (cannot be mapped to a flow) and malformed data.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> d, out IPAddress? addr, out ushort port, out int payloadOffset)
    {
        addr = null; port = 0; payloadOffset = 0;
        if (d.Length < 10 || d[2] != 0) return false;
        int alen;
        if (d[3] == 1) alen = 4; else if (d[3] == 4) alen = 16; else return false;
        if (d.Length < 4 + alen + 2) return false;
        addr = new IPAddress(d.Slice(4, alen));
        port = (ushort)((d[4 + alen] << 8) | d[5 + alen]);
        payloadOffset = 6 + alen;
        return true;
    }
}

/// <summary>One SOCKS5 UDP ASSOCIATE session (a control TCP connection plus a UDP socket to the relay).</summary>
public sealed class Socks5UdpSession : IDisposable
{
    private readonly Socket _control;
    private readonly Socket _udp;
    private readonly CancellationTokenSource _cts = new();
    public long LastActivity = Environment.TickCount64;
    public bool IsClosed { get; private set; }
    public Func<IPAddress, ushort, byte[], Task>? OnDatagram;

    private Socks5UdpSession(Socket control, Socket udp) { _control = control; _udp = udp; }

    public static async Task<Socks5UdpSession> CreateAsync(ProxySettings p, CancellationToken ct)
    {
        if (p.Type != ProxyType.Socks5) throw new ProxyException("UDP needs a SOCKS5 proxy.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ProxyDialer.HandshakeTimeout);
        var control = await ProxyDialer.ConnectToProxyAsync(p, cts.Token).ConfigureAwait(false);
        try
        {
            await ProxyDialer.Socks5HandshakeAsync(control, p, cts.Token).ConfigureAwait(false);
            var (bnd, bport) = await ProxyDialer.Socks5CommandAsync(control, 0x03, null, IPAddress.Any, 0, cts.Token).ConfigureAwait(false);
            var proxyIp = ((IPEndPoint)control.RemoteEndPoint!).Address;
            if (bnd == null || bnd.Equals(IPAddress.Any) || bnd.Equals(IPAddress.IPv6Any)) bnd = proxyIp;
            if (bport == 0) throw new ProxyException("The proxy did not provide a UDP relay port (UDP not supported?).");
            var udp = new Socket(bnd.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            DisableConnReset(udp);
            await udp.ConnectAsync(new IPEndPoint(bnd, bport), cts.Token).ConfigureAwait(false);
            var s = new Socks5UdpSession(control, udp);
            _ = s.ReceiveLoop();
            _ = s.ControlWatch();
            return s;
        }
        catch { control.Dispose(); throw; }
    }

    internal static void DisableConnReset(Socket s)
    {
        if (!OperatingSystem.IsWindows()) return;
        try { s.IOControl(unchecked((int)0x9800000C), new byte[] { 0 }, null); } catch { }
    }

    public async Task SendToAsync(IPAddress dst, ushort port, ReadOnlyMemory<byte> payload)
    {
        if (IsClosed) throw new ObjectDisposedException(nameof(Socks5UdpSession));
        LastActivity = Environment.TickCount64;
        await _udp.SendAsync(Socks5UdpCodec.Encode(dst, port, payload.Span), SocketFlags.None).ConfigureAwait(false);
    }

    private async Task ReceiveLoop()
    {
        var buf = new byte[65535];
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                int n;
                try { n = await _udp.ReceiveAsync(buf, SocketFlags.None, _cts.Token).ConfigureAwait(false); }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset) { continue; }
                if (!Socks5UdpCodec.TryDecode(buf.AsSpan(0, n), out var a, out var port, out var off)) continue;
                LastActivity = Environment.TickCount64;
                var cb = OnDatagram;
                if (cb != null) await cb(a!, port, buf.AsSpan(off, n - off).ToArray()).ConfigureAwait(false);
            }
        }
        catch { }
        finally { Dispose(); }
    }

    // The association lives as long as the control connection does (RFC 1928).
    private async Task ControlWatch()
    {
        var b = new byte[16];
        try { while (await _control.ReceiveAsync(b, SocketFlags.None, _cts.Token).ConfigureAwait(false) > 0) { } }
        catch { }
        Dispose();
    }

    public void Dispose()
    {
        if (IsClosed) return;
        IsClosed = true;
        try { _cts.Cancel(); } catch { }
        try { _udp.Dispose(); } catch { }
        try { _control.Dispose(); } catch { }
    }
}
