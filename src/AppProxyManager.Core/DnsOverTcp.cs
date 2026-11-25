using System.Net;
using System.Net.Sockets;

namespace AppProxyManager.Core;

/// <summary>
/// Resolves a DNS wire-format query by sending it over a TCP connection tunnelled through the proxy
/// (RFC 1035 §4.2.2 framing). Works with both SOCKS5 and HTTP proxies, so DNS never touches the local network.
/// </summary>
public static class DnsOverTcp
{
    public static async Task<byte[]> QueryAsync(ProxySettings p, IPAddress resolver, byte[] query, CancellationToken ct)
    {
        if (query.Length is < 12 or > 65535) throw new ArgumentException("Not a DNS message.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(8));
        using var s = await ProxyDialer.ConnectTcpAsync(p, resolver, 53, cts.Token).ConfigureAwait(false);
        var framed = new byte[2 + query.Length];
        framed[0] = (byte)(query.Length >> 8); framed[1] = (byte)query.Length;
        query.CopyTo(framed, 2);
        await s.SendAsync(framed, SocketFlags.None, cts.Token).ConfigureAwait(false);
        var lenBuf = new byte[2];
        await ProxyDialer.ReadExactAsync(s, lenBuf, 2, cts.Token).ConfigureAwait(false);
        int len = (lenBuf[0] << 8) | lenBuf[1];
        var resp = new byte[len];
        await ProxyDialer.ReadExactAsync(s, resp, len, cts.Token).ConfigureAwait(false);
        return resp;
    }
}
