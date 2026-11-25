namespace AppProxyManager.Core;

public enum Verdict
{
    /// <summary>Not ours: re-inject the packet unchanged (direct connection).</summary>
    Pass,
    /// <summary>Deliberately discarded (IPv6 / UDP of routed apps that cannot be proxied: dropped instead of leaking).</summary>
    Drop,
    /// <summary>Packet was rewritten in place and must be injected as INBOUND so the local redirector/relay (or the app) receives it.</summary>
    ReinjectInbound
}

/// <summary>
/// The decision logic of the packet engine, free of any driver calls so it can be unit-tested.
///
/// Reflection trick (same idea as WinDivert's "streamdump"): an outbound packet (local:cport -> dst:dport) of a routed process is
/// rewritten to (dst:cport -> local:redirPort) and injected inbound. The local redirector therefore sees a client whose address
/// is the ORIGINAL destination, which is how it recovers where the app really wanted to go. Replies from the redirector
/// (local:redirPort -> dst:cport) are rewritten to (dst:dport -> local:cport), so the app believes it talks to the real server.
/// </summary>
public sealed class PacketTranslator
{
    private const byte Tcp = 6, Udp = 17;
    private readonly NatTable _tcpNat, _udpNat;
    private readonly PidTable _pids;
    private readonly RoutingPolicy _policy;
    private readonly Func<AppConfig> _cfg;
    private readonly Func<int> _tcpPort, _udpPort, _dnsPid;
    private readonly Action<string?> _onRouted;

    public long ProxiedTcpFlows, ProxiedUdpDatagrams, ProxiedDnsQueries, DroppedIPv6, DroppedUdp;

    public PacketTranslator(NatTable tcpNat, NatTable udpNat, PidTable pids, RoutingPolicy policy, Func<AppConfig> cfg,
        Func<int> tcpPort, Func<int> udpPort, Func<int> dnsPid, Action<string?>? onRouted = null)
    {
        _tcpNat = tcpNat; _udpNat = udpNat; _pids = pids; _policy = policy; _cfg = cfg;
        _tcpPort = tcpPort; _udpPort = udpPort; _dnsPid = dnsPid; _onRouted = onRouted ?? (_ => { });
    }

    public Verdict Translate(byte[] b, int len)
    {
        int ver = b[0] >> 4;
        if (ver == 6) return TranslateV6(b, len);
        if (ver != 4) return Verdict.Pass;
        var p = PacketRewriter.ParseV4(b, len);
        if (!p.Valid) return Verdict.Pass;
        return p.Protocol == Tcp ? TranslateTcp(b, len, p) : TranslateUdp(b, len, p);
    }

    private Verdict TranslateV6(byte[] b, int len)
    {
        if (!_cfg().BlockIPv6ForRoutedApps || !_policy.HasRules) return Verdict.Pass;
        if (!PacketRewriter.TryParseV6(b, len, out byte proto, out ushort sport, out _)) return Verdict.Pass;
        int pid = _pids.Lookup(proto, sport);
        if (pid == 0 || !_policy.IsRouted(pid, out _)) return Verdict.Pass;
        Interlocked.Increment(ref DroppedIPv6);   // the app falls back to IPv4, which can be proxied
        return Verdict.Drop;
    }

    private Verdict TranslateTcp(byte[] b, int len, PacketInfo p)
    {
        int redir = _tcpPort();
        if (redir == 0) return Verdict.Pass;

        // redirector -> client
        if (p.SrcPort == redir)
        {
            if (!_tcpNat.TryGet(new FlowKey(p.DstPort, p.DstIp), out var e)) return Verdict.Pass;
            PacketRewriter.Rewrite(b, len, p.DstIp, e.OrigPort, e.LocalIp, null);
            return Verdict.ReinjectInbound;
        }

        var key = new FlowKey(p.SrcPort, p.DstIp);
        if (p.IsSyn)
        {
            var cfg = _cfg();
            if (IpUtil.IsLoopback(p.DstIp) || (cfg.BypassLan && IpUtil.IsLanOrSpecial(p.DstIp))) { _tcpNat.Remove(key); return Verdict.Pass; }
            int pid = _pids.Lookup(Tcp, p.SrcPort);
            if (pid == 0 || !_policy.IsRouted(pid, out string? path)) { _tcpNat.Remove(key); return Verdict.Pass; }
            _tcpNat.Set(key, new NatEntry { LocalIp = p.SrcIp, OrigPort = p.DstPort, Pid = pid });
            Interlocked.Increment(ref ProxiedTcpFlows);
            _onRouted(path);
        }
        else if (!_tcpNat.TryGet(key, out _)) return Verdict.Pass;   // not a redirected flow: connections opened before routing stay direct

        // client -> server
        PacketRewriter.Rewrite(b, len, p.DstIp, null, p.SrcIp, (ushort)redir);
        return Verdict.ReinjectInbound;
    }

    private Verdict TranslateUdp(byte[] b, int len, PacketInfo p)
    {
        int relay = _udpPort();
        if (relay == 0) return Verdict.Pass;

        // relay -> client
        if (p.SrcPort == relay)
        {
            if (!_udpNat.TryGet(new FlowKey(p.DstPort, p.DstIp), out var e)) return Verdict.Pass;
            PacketRewriter.Rewrite(b, len, p.DstIp, e.OrigPort, e.LocalIp, null);
            return Verdict.ReinjectInbound;
        }

        var cfg = _cfg();
        bool isDnsPort = p.DstPort == 53;
        if (!isDnsPort && !_policy.HasRules) return Verdict.Pass;
        if (IpUtil.IsLoopback(p.DstIp)) return Verdict.Pass;

        int pid = _pids.Lookup(Udp, p.SrcPort);
        if (pid == 0) return Verdict.Pass;
        bool routed = _policy.IsRouted(pid, out string? path);
        bool dns;
        if (routed) dns = isDnsPort;
        else if (isDnsPort && cfg.RouteSystemDns && _dnsPid() != 0 && pid == _dnsPid()) dns = true;   // opt-in: Windows DNS Client
        else return Verdict.Pass;

        if (!dns)
        {
            if (cfg.BypassLan && IpUtil.IsLanOrSpecial(p.DstIp)) return Verdict.Pass;
            if (cfg.Proxy.Type != ProxyType.Socks5) { Interlocked.Increment(ref DroppedUdp); return Verdict.Drop; } // HTTP proxies cannot carry UDP
        }
        _udpNat.Set(new FlowKey(p.SrcPort, p.DstIp), new NatEntry { LocalIp = p.SrcIp, OrigPort = p.DstPort, Pid = pid, IsDns = dns });
        if (dns) Interlocked.Increment(ref ProxiedDnsQueries); else Interlocked.Increment(ref ProxiedUdpDatagrams);
        if (routed) _onRouted(path);

        PacketRewriter.Rewrite(b, len, p.DstIp, null, p.SrcIp, (ushort)relay);
        return Verdict.ReinjectInbound;
    }
}
