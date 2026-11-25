using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AppProxyManager.Core;

public sealed record ProxyTestResult(bool Ok, string Message, string? ExitIp, int LatencyMs);

public static class ProxyHealth
{
    private static readonly string[] IpEchoHosts = { "api.ipify.org", "icanhazip.com" };

    /// <summary>Cheap liveness probe: TCP connect plus (for SOCKS5) method negotiation. Always bounded by a timeout.</summary>
    public static async Task<(bool Ok, string? Error)> ProbeAsync(ProxySettings p, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(4));
            using var s = await ProxyDialer.ConnectToProxyAsync(p, cts.Token).ConfigureAwait(false);
            if (p.Type == ProxyType.Socks5) await ProxyDialer.Socks5HandshakeAsync(s, p, cts.Token).ConfigureAwait(false);
            return (true, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (false, p.Type == ProxyType.Socks5
                ? "The server did not answer the SOCKS5 handshake. Is this an HTTP proxy? Check the proxy type."
                : "The proxy did not answer in time.");
        }
        catch (Exception e) { return (false, e.Message); }
    }

    public static async Task<bool> IsAliveAsync(ProxySettings p, CancellationToken ct) =>
        (await ProbeAsync(p, ct).ConfigureAwait(false)).Ok;

    /// <summary>Full test: reaches the Internet through the proxy and reports the exit IP address.</summary>
    public static async Task<ProxyTestResult> TestAsync(ProxySettings p, CancellationToken ct, string[]? echoHosts = null, int echoPort = 80)
    {
        var sw = Stopwatch.StartNew();
        var probe = await ProbeAsync(p, ct).ConfigureAwait(false);
        if (!probe.Ok) return new(false, probe.Error ?? "Proxy is not reachable.", null, (int)sw.ElapsedMilliseconds);
        string? lastError = null;
        foreach (var host in echoHosts ?? IpEchoHosts)
        {
            try
            {
                using var s = await ProxyDialer.ConnectTcpAsync(p, host, echoPort, ct).ConfigureAwait(false);
                await s.SendAsync(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"), SocketFlags.None, ct).ConfigureAwait(false);
                var sb = new StringBuilder();
                var buf = new byte[2048];
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(8));
                int n;
                while (sb.Length < 8192 && !ResponseComplete(sb.ToString()) &&
                       (n = await s.ReceiveAsync(buf, SocketFlags.None, cts.Token).ConfigureAwait(false)) > 0)
                    sb.Append(Encoding.ASCII.GetString(buf, 0, n));
                var ip = ExtractIp(sb.ToString());
                if (ip != null) return new(true, "Connected. Traffic exits via " + ip, ip, (int)sw.ElapsedMilliseconds);
                lastError = "unexpected reply from " + host;
            }
            catch (Exception e) { lastError = e.Message; }
        }
        return new(true, $"Proxy is reachable, but the Internet check failed ({lastError}).", null, (int)sw.ElapsedMilliseconds);
    }

    /// <summary>True once the HTTP response is complete: Content-Length satisfied or chunked terminator seen.</summary>
    internal static bool ResponseComplete(string text)
    {
        int i = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (i < 0) return false;
        var head = text[..i];
        var body = text[(i + 4)..];
        foreach (var line in head.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(line[15..].Trim(), out int cl)) return body.Length >= cl;
            if (line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase) &&
                line.Contains("chunked", StringComparison.OrdinalIgnoreCase)) return body.EndsWith("0\r\n\r\n", StringComparison.Ordinal);
        }
        return false; // unknown length: wait for the server to close the connection
    }

    /// <summary>Finds the first complete IPv4/IPv6 literal in the HTTP body (plain or chunked).</summary>
    internal static string? ExtractIp(string text)
    {
        int i = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var body = i >= 0 ? text[(i + 4)..] : text;
        foreach (var tok in body.Split(new[] { '\r', '\n', ' ', '"', ',', '{', '}' }, StringSplitOptions.RemoveEmptyEntries))
            if (IPAddress.TryParse(tok, out var ip) &&
                ((ip.AddressFamily == AddressFamily.InterNetwork && tok.Count(c => c == '.') == 3) || ip.AddressFamily == AddressFamily.InterNetworkV6))
                return ip.ToString();
        return null;
    }
}

/// <summary>Polls the proxy so the UI can show outages and recovery.</summary>
public sealed class ProxyMonitor : IDisposable
{
    private readonly Func<ProxySettings> _get;
    private readonly CancellationTokenSource _cts = new();
    public bool IsUp { get; private set; }
    public event Action<bool>? StateChanged;

    public ProxyMonitor(Func<ProxySettings> get) { _get = get; }

    public void Start() => _ = Loop();

    private async Task Loop()
    {
        bool? last = null;
        while (!_cts.IsCancellationRequested)
        {
            bool up = await ProxyHealth.IsAliveAsync(_get(), _cts.Token).ConfigureAwait(false);
            IsUp = up;
            if (last != up) { last = up; StateChanged?.Invoke(up); }
            try { await Task.Delay(up ? 5000 : 2000, _cts.Token).ConfigureAwait(false); } catch { return; }
        }
    }

    public void Dispose() => _cts.Cancel();
}
