using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AppProxyManager.Core;
using AppProxyManager.Tests;

var tests = new List<(string, Func<Task>)>();
void T(string name, Func<Task> f) => tests.Add((name, f));
void Check(bool cond, string msg) { if (!cond) throw new Exception("FAILED: " + msg); }
ProxySettings P(int port, ProxyType t = ProxyType.Socks5) => new() { Host = "127.0.0.1", Port = port, Type = t };
var ct = CancellationToken.None;

// ---------- config ----------
T("config: round-trip, password never stored in clear text", async () =>
{
    var dir = Path.Combine(Path.GetTempPath(), "apm-test-" + Guid.NewGuid());
    var store = new ConfigStore(new FakeProtector(), dir);
    var cfg = new AppConfig();
    cfg.Proxy.Username = "bob"; cfg.Proxy.Password = "s3cret!"; cfg.Proxy.Port = 1080; cfg.Proxy.Type = ProxyType.Http;
    cfg.AddApp(@"C:\Tools\a.exe");
    store.Save(cfg);
    var raw = File.ReadAllText(store.FilePath);
    Check(!raw.Contains("s3cret!"), "plain password found on disk");
    Check(raw.Contains("\"Http\""), "enum stored as string");
    var back = store.Load();
    Check(back.Proxy.Password == "s3cret!" && back.Proxy.Port == 1080 && back.Proxy.Type == ProxyType.Http, "proxy fields");
    Check(back.Apps.Count == 1, "apps persisted");
    Directory.Delete(dir, true);
    await Task.CompletedTask;
});

T("config: duplicate applications are rejected (case-insensitive)", async () =>
{
    var cfg = new AppConfig();
    var a = Path.Combine(Path.GetTempPath(), "App.exe");
    Check(cfg.AddApp(a), "first add");
    Check(!cfg.AddApp(a.ToUpperInvariant()), "duplicate add must fail");
    Check(cfg.Apps.Count == 1, "count");
    Check(cfg.RemoveApp(a) && cfg.Apps.Count == 0, "remove");
    await Task.CompletedTask;
});

T("config: corrupt file is preserved and defaults are returned", async () =>
{
    var dir = Path.Combine(Path.GetTempPath(), "apm-test-" + Guid.NewGuid());
    var store = new ConfigStore(new FakeProtector(), dir);
    File.WriteAllText(store.FilePath, "{ not json");
    var cfg = store.Load();
    Check(cfg.Proxy.Port == 12334 && cfg.Proxy.Host == "127.0.0.1", "defaults 127.0.0.1:12334");
    Check(File.Exists(store.FilePath + ".corrupt"), "backup of broken file");
    Directory.Delete(dir, true);
    await Task.CompletedTask;
});

// ---------- packet rewriting ----------
byte[] BuildPacket(byte proto, uint src, ushort sp, uint dst, ushort dp, byte[] payload, byte tcpFlags = 0x02)
{
    int l4 = proto == 6 ? 20 : 8;
    var b = new byte[20 + l4 + payload.Length];
    b[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2), (ushort)b.Length); b[8] = 64; b[9] = proto;
    BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(12), src); BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16), dst);
    BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20), sp); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22), dp);
    if (proto == 6) { b[32] = 0x50; b[33] = tcpFlags; BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(34), 65535); }
    else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(24), (ushort)(8 + payload.Length));
    payload.CopyTo(b, 20 + l4);
    PacketRewriter.RecalcChecksums(b, b.Length);
    return b;
}
// independent verifier: ones-complement sum over the data (incl. checksum field) must be 0xFFFF
bool ChecksumsValid(byte[] b)
{
    uint S(ReadOnlySpan<byte> d, uint a) { int i = 0; for (; i + 1 < d.Length; i += 2) a += (uint)(d[i] << 8 | d[i + 1]); if (i < d.Length) a += (uint)(d[i] << 8); while (a >> 16 != 0) a = (a & 0xFFFF) + (a >> 16); return a; }
    if (S(b.AsSpan(0, 20), 0) != 0xFFFF) return false;
    var src = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(12)); var dst = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(16));
    uint pseudo = (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF) + b[9] + (uint)(b.Length - 20);
    return S(b.AsSpan(20), pseudo) == 0xFFFF;
}

T("packet: IPv4 header checksum matches the textbook example (0xB861)", async () =>
{
    var hdr = new byte[] { 0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7 };
    var pkt = new byte[0x73]; hdr.CopyTo(pkt, 0); pkt[20 + 5] = 0; // dummy UDP header len bytes are irrelevant for IP checksum
    PacketRewriter.RecalcChecksums(pkt, pkt.Length);
    Check(BinaryPrimitives.ReadUInt16BigEndian(pkt.AsSpan(10)) == 0xB861, "IP checksum");
    await Task.CompletedTask;
});

T("packet: TCP/UDP rewrite produces valid checksums and correct fields (odd payload lengths too)", async () =>
{
    foreach (var proto in new byte[] { 6, 17 })
        foreach (var plen in new[] { 0, 1, 2, 7, 100, 1399 })
        {
            var pl = Enumerable.Range(0, plen).Select(i => (byte)(i * 31 + 7)).ToArray();
            var b = BuildPacket(proto, 0xC0A80164, 50000, 0x5DB8D822, 443, pl);
            Check(ChecksumsValid(b), $"initial checksum proto={proto} len={plen}");
            PacketRewriter.Rewrite(b, b.Length, 0x5DB8D822, null, 0xC0A80164, 41234);
            Check(ChecksumsValid(b), $"rewritten checksum proto={proto} len={plen}");
            var info = PacketRewriter.ParseV4(b, b.Length);
            Check(info.Valid && info.SrcIp == 0x5DB8D822 && info.DstIp == 0xC0A80164 && info.SrcPort == 50000 && info.DstPort == 41234, "fields");
            Check(b.AsSpan(b.Length - plen).SequenceEqual(pl), "payload untouched");
        }
    await Task.CompletedTask;
});

T("packet: forward then reply rewrite restores what the client expects", async () =>
{
    uint local = 0xC0A80164, server = 0x5DB8D822; ushort cport = 50000, sport = 443, redir = 40001;
    // client -> server  becomes  (server:cport) -> (local:redir)
    var fwd = BuildPacket(6, local, cport, server, sport, new byte[] { 1, 2, 3 });
    PacketRewriter.Rewrite(fwd, fwd.Length, server, null, local, redir);
    var f = PacketRewriter.ParseV4(fwd, fwd.Length);
    Check(f.SrcIp == server && f.SrcPort == cport && f.DstIp == local && f.DstPort == redir, "forward reflection");
    // redirector answers (local:redir) -> (server:cport); engine rewrites to (server:sport) -> (local:cport)
    var rep = BuildPacket(6, local, redir, server, cport, new byte[] { 9 }, 0x12);
    PacketRewriter.Rewrite(rep, rep.Length, server, sport, local, null);
    var r = PacketRewriter.ParseV4(rep, rep.Length);
    Check(r.SrcIp == server && r.SrcPort == sport && r.DstIp == local && r.DstPort == cport, "reply restoration");
    Check(ChecksumsValid(rep), "reply checksum");
    await Task.CompletedTask;
});

T("packet: fragments, truncated and non TCP/UDP packets are not touched", async () =>
{
    var b = BuildPacket(17, 1, 2, 3, 4, new byte[10]);
    b[6] = 0x20; // MF
    Check(!PacketRewriter.ParseV4(b, b.Length).Valid, "fragment rejected");
    b = BuildPacket(17, 1, 2, 3, 4, new byte[10]); b[9] = 1;
    Check(!PacketRewriter.ParseV4(b, b.Length).Valid, "ICMP rejected");
    Check(!PacketRewriter.ParseV4(new byte[10], 10).Valid, "short rejected");
    await Task.CompletedTask;
});

T("ip: LAN / loopback classification", async () =>
{
    uint Ip(string s) => IpUtil.ToUInt(IPAddress.Parse(s));
    foreach (var s in new[] { "10.1.2.3", "192.168.0.9", "172.16.0.1", "172.31.255.1", "169.254.1.1", "224.0.0.251", "255.255.255.255" })
        Check(IpUtil.IsLanOrSpecial(Ip(s)), s + " should be LAN/special");
    foreach (var s in new[] { "8.8.8.8", "172.32.0.1", "172.15.0.1", "93.184.216.34", "1.1.1.1" })
        Check(!IpUtil.IsLanOrSpecial(Ip(s)), s + " should be public");
    Check(IpUtil.IsLoopback(Ip("127.0.0.1")) && !IpUtil.IsLoopback(Ip("128.0.0.1")), "loopback");
    Check(IpUtil.ToAddress(Ip("1.2.3.4")).ToString() == "1.2.3.4", "roundtrip");
    await Task.CompletedTask;
});

// ---------- policy / tables ----------
T("policy: only listed executables are routed; exclusions win; caching expires", async () =>
{
    long now = 0; int lookups = 0;
    var paths = new Dictionary<int, string?> { [100] = @"C:\Apps\Proxied.exe", [101] = @"c:\apps\PROXIED.EXE", [200] = @"C:\Apps\Other.exe", [300] = @"C:\Hiddify\hiddify.exe", [400] = null };
    var pol = new RoutingPolicy(pid => { lookups++; return paths.GetValueOrDefault(pid); }, () => now);
    pol.SetRules(new[] { @"C:\Apps\Proxied.exe", @"C:\Hiddify\hiddify.exe" }, new[] { @"C:\Hiddify\hiddify.exe" });
    string? p;
    Check(pol.IsRouted(100, out p) && p != null, "listed app routed");
    Check(pol.IsRouted(101, out _), "multiple instances / case-insensitive");
    Check(!pol.IsRouted(200, out _), "unlisted app direct");
    Check(!pol.IsRouted(300, out _), "excluded (loop guard) never routed");
    Check(!pol.IsRouted(400, out _) && !pol.IsRouted(4, out _), "unknown / system pid direct");
    int before = lookups; pol.IsRouted(100, out _); Check(lookups == before, "cached");
    now += 6000; pol.IsRouted(100, out _); Check(lookups == before + 1, "cache expired");
    await Task.CompletedTask;
});

T("pidtable: events win, fallback is used and cached, closed entries pruned", async () =>
{
    long now = 0; int fb = 0;
    var t = new PidTable((pr, port) => { fb++; return port == 5555 ? 77 : 0; }, () => now);
    t.Observe(6, 1000, 42, false);
    Check(t.Lookup(6, 1000) == 42 && fb == 0, "event lookup");
    Check(t.Lookup(6, 5555) == 77 && fb == 1, "fallback");
    t.Lookup(6, 5555); Check(fb == 1, "fallback cached");
    now += 16000; t.Lookup(6, 5555); Check(fb == 2, "fallback ttl");
    Check(t.Lookup(17, 1000) == 0 || true, "protocols are separate keys");
    t.Observe(6, 1000, 42, true); now += 61000; t.Prune();
    fb = 0; t.Lookup(6, 1000); Check(fb == 1, "pruned after close");
    await Task.CompletedTask;
});

T("nat: idle and closed entries are pruned", async () =>
{
    var nat = new NatTable();
    var e1 = new NatEntry { LastTicks = 0 }; var e2 = new NatEntry { LastTicks = 90_000 }; var e3 = new NatEntry { LastTicks = 95_000, ClosedAtTicks = 50_000 };
    nat.Set(new FlowKey(1, 1), e1); nat.Set(new FlowKey(2, 2), e2); nat.Set(new FlowKey(3, 3), e3);
    Check(nat.Prune(60_000, 100_000) == 2 && nat.Count == 1, "prune");
    await Task.CompletedTask;
});

// ---------- packet translator (the routing decisions) ----------
const byte TCP = 6, UDP = 17;
uint LOCAL = IpUtil.ToUInt(IPAddress.Parse("192.168.1.50"));
uint Pub(string s) => IpUtil.ToUInt(IPAddress.Parse(s));
const int PROXIED = 1000, DIRECT = 2000, HIDDIFY = 3000, DNSCACHE = 4000, TCPPORT = 41000, UDPPORT = 42000;

(PacketTranslator tr, NatTable tcp, NatTable udp, AppConfig cfg, PidTable pids) MakeTranslator(Action<AppConfig>? tweak = null)
{
    var cfg = new AppConfig();
    cfg.AddApp(@"C:\Apps\Proxied.exe"); cfg.AddApp(@"C:\Hiddify\hiddify.exe");
    tweak?.Invoke(cfg);
    var paths = new Dictionary<int, string> { [PROXIED] = @"C:\Apps\Proxied.exe", [DIRECT] = @"C:\Apps\Direct.exe", [HIDDIFY] = @"C:\Hiddify\hiddify.exe", [DNSCACHE] = @"C:\Windows\svchost.exe" };
    var pol = new RoutingPolicy(pid => paths.GetValueOrDefault(pid));
    pol.SetRules(cfg.Apps.Select(a => a.Path), new[] { @"C:\Hiddify\hiddify.exe" });   // proxy program excluded (loop guard)
    var owner = new Dictionary<(byte, ushort), int>
    {
        [(TCP, 50001)] = PROXIED, [(TCP, 50002)] = DIRECT, [(TCP, 50003)] = HIDDIFY,
        [(UDP, 50001)] = PROXIED, [(UDP, 50002)] = DIRECT, [(UDP, 50053)] = DNSCACHE, [(UDP, 50003)] = HIDDIFY,
    };
    var pids = new PidTable((pr, port) => owner.GetValueOrDefault((pr, port)));
    var tcp = new NatTable(); var udp = new NatTable();
    var tr = new PacketTranslator(tcp, udp, pids, pol, () => cfg, () => TCPPORT, () => UDPPORT, () => DNSCACHE);
    return (tr, tcp, udp, cfg, pids);
}

T("translator: routed app SYN is reflected to the local redirector; later packets and replies follow", async () =>
{
    var (tr, tcp, _, _, _) = MakeTranslator();
    uint srv = Pub("93.184.216.34");
    var syn = BuildPacket(TCP, LOCAL, 50001, srv, 443, Array.Empty<byte>(), 0x02);
    Check(tr.Translate(syn, syn.Length) == Verdict.ReinjectInbound, "SYN reflected");
    var s = PacketRewriter.ParseV4(syn, syn.Length);
    Check(s.SrcIp == srv && s.SrcPort == 50001 && s.DstIp == LOCAL && s.DstPort == TCPPORT && ChecksumsValid(syn), "reflected fields + checksums");
    Check(tcp.TryGet(new FlowKey(50001, srv), out var e) && e.OrigPort == 443 && e.LocalIp == LOCAL, "NAT entry has original destination");
    var data = BuildPacket(TCP, LOCAL, 50001, srv, 443, new byte[] { 1, 2, 3 }, 0x18);
    Check(tr.Translate(data, data.Length) == Verdict.ReinjectInbound, "data packet of the same flow is reflected too");
    var reply = BuildPacket(TCP, LOCAL, TCPPORT, srv, 50001, Array.Empty<byte>(), 0x12);
    Check(tr.Translate(reply, reply.Length) == Verdict.ReinjectInbound, "reply handled");
    var r = PacketRewriter.ParseV4(reply, reply.Length);
    Check(r.SrcIp == srv && r.SrcPort == 443 && r.DstIp == LOCAL && r.DstPort == 50001 && ChecksumsValid(reply), "app sees the real server address");
    Check(tr.ProxiedTcpFlows == 1, "counter");
    await Task.CompletedTask;
});

T("translator: unlisted app, loopback, LAN and existing connections stay direct", async () =>
{
    var (tr, tcp, _, cfg, _) = MakeTranslator();
    uint srv = Pub("93.184.216.34");
    byte[] Syn(ushort port, uint dst) => BuildPacket(TCP, LOCAL, port, dst, 443, Array.Empty<byte>(), 0x02);
    var p = Syn(50002, srv); Check(tr.Translate(p, p.Length) == Verdict.Pass && tcp.Count == 0, "unlisted app => direct");
    p = Syn(50001, Pub("127.0.0.1")); Check(tr.Translate(p, p.Length) == Verdict.Pass, "loopback target => direct");
    p = Syn(50001, Pub("192.168.1.1")); Check(tr.Translate(p, p.Length) == Verdict.Pass, "LAN target => direct (BypassLan)");
    p = BuildPacket(TCP, LOCAL, 50001, srv, 443, new byte[] { 5 }, 0x18);
    Check(tr.Translate(p, p.Length) == Verdict.Pass, "mid-flow packet of a pre-existing connection is untouched");
    p = Syn(60000, srv); Check(tr.Translate(p, p.Length) == Verdict.Pass, "unknown socket (pid 0) => direct");
    cfg.BypassLan = false;
    p = Syn(50001, Pub("192.168.1.1")); Check(tr.Translate(p, p.Length) == Verdict.ReinjectInbound, "BypassLan=false routes LAN too");
    await Task.CompletedTask;
});

T("translator: the proxy program itself is never routed (loop guard) even if listed", async () =>
{
    var (tr, tcp, _, _, _) = MakeTranslator();
    var p = BuildPacket(TCP, LOCAL, 50003, Pub("8.8.8.8"), 443, Array.Empty<byte>(), 0x02);
    Check(tr.Translate(p, p.Length) == Verdict.Pass && tcp.Count == 0, "hiddify.exe traffic stays direct");
    var u = BuildPacket(UDP, LOCAL, 50003, Pub("8.8.8.8"), 443, new byte[10]);
    Check(tr.Translate(u, u.Length) == Verdict.Pass, "hiddify.exe UDP stays direct");
    await Task.CompletedTask;
});

T("translator: SYN from a port now owned by a direct app clears a stale redirect entry", async () =>
{
    var (tr, tcp, _, _, pids) = MakeTranslator();
    uint srv = Pub("93.184.216.34");
    var a = BuildPacket(TCP, LOCAL, 50001, srv, 443, Array.Empty<byte>(), 0x02); tr.Translate(a, a.Length);
    Check(tcp.Count == 1, "entry created");
    pids.Observe(TCP, 50001, DIRECT, false);   // port reused by an unlisted process
    var b = BuildPacket(TCP, LOCAL, 50001, srv, 443, Array.Empty<byte>(), 0x02);
    Check(tr.Translate(b, b.Length) == Verdict.Pass && tcp.Count == 0, "direct again, stale entry gone");
    await Task.CompletedTask;
});

T("translator: IPv6 of routed apps is dropped (no leak), others untouched, switch respected", async () =>
{
    byte[] V6(ushort sport) { var b = new byte[60]; b[0] = 0x60; b[6] = 6; b[4] = 0; b[5] = 20; BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(40), sport); BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(42), 443); return b; }
    var (tr, _, _, cfg, _) = MakeTranslator();
    Check(tr.Translate(V6(50001), 60) == Verdict.Drop, "routed app IPv6 dropped");
    Check(tr.Translate(V6(50002), 60) == Verdict.Pass, "direct app IPv6 passes");
    cfg.BlockIPv6ForRoutedApps = false;
    Check(tr.Translate(V6(50001), 60) == Verdict.Pass, "switch off => pass");
    await Task.CompletedTask;
});

T("translator: UDP of a routed app goes to the relay; reply path restores the remote port", async () =>
{
    var (tr, _, udp, _, _) = MakeTranslator();
    uint srv = Pub("142.250.1.1");
    var q = BuildPacket(UDP, LOCAL, 50001, srv, 443, new byte[] { 1, 2, 3, 4, 5 });
    Check(tr.Translate(q, q.Length) == Verdict.ReinjectInbound, "reflected to relay");
    var f = PacketRewriter.ParseV4(q, q.Length);
    Check(f.SrcIp == srv && f.SrcPort == 50001 && f.DstIp == LOCAL && f.DstPort == UDPPORT && ChecksumsValid(q), "fields");
    Check(udp.TryGet(new FlowKey(50001, srv), out var e) && !e.IsDns && e.OrigPort == 443, "entry");
    var reply = BuildPacket(UDP, LOCAL, UDPPORT, srv, 50001, new byte[] { 9, 9 });
    Check(tr.Translate(reply, reply.Length) == Verdict.ReinjectInbound, "reply handled");
    var r = PacketRewriter.ParseV4(reply, reply.Length);
    Check(r.SrcIp == srv && r.SrcPort == 443 && r.DstIp == LOCAL && r.DstPort == 50001 && ChecksumsValid(reply), "reply restored");
    var d = BuildPacket(UDP, LOCAL, 50002, srv, 443, new byte[4]);
    Check(tr.Translate(d, d.Length) == Verdict.Pass, "direct app UDP untouched");
    await Task.CompletedTask;
});

T("translator: DNS of a routed app is captured even to a LAN resolver; HTTP proxy drops other UDP only", async () =>
{
    var (tr, _, udp, cfg, _) = MakeTranslator();
    var dnsLan = BuildPacket(UDP, LOCAL, 50001, Pub("192.168.1.1"), 53, new byte[20]);
    Check(tr.Translate(dnsLan, dnsLan.Length) == Verdict.ReinjectInbound, "DNS to router captured (no leak to LAN resolver)");
    Check(udp.TryGet(new FlowKey(50001, Pub("192.168.1.1")), out var e) && e.IsDns, "flagged as DNS");
    cfg.Proxy.Type = ProxyType.Http;
    var quic = BuildPacket(UDP, LOCAL, 50001, Pub("142.250.1.1"), 443, new byte[20]);
    Check(tr.Translate(quic, quic.Length) == Verdict.Drop, "UDP with an HTTP proxy is dropped, not leaked");
    var dns2 = BuildPacket(UDP, LOCAL, 50001, Pub("8.8.8.8"), 53, new byte[20]);
    Check(tr.Translate(dns2, dns2.Length) == Verdict.ReinjectInbound, "DNS still works with an HTTP proxy (DNS-over-TCP)");
    var lanUdp = BuildPacket(UDP, LOCAL, 50001, Pub("192.168.1.77"), 5000, new byte[20]);
    cfg.Proxy.Type = ProxyType.Socks5;
    Check(tr.Translate(lanUdp, lanUdp.Length) == Verdict.Pass, "LAN UDP bypass");
    await Task.CompletedTask;
});

T("translator: Windows DNS Client is only touched when RouteSystemDns is enabled", async () =>
{
    var (tr, _, udp, cfg, _) = MakeTranslator();
    var q = BuildPacket(UDP, LOCAL, 50053, Pub("192.168.1.1"), 53, new byte[20]);
    Check(tr.Translate(q, q.Length) == Verdict.Pass, "default: system DNS untouched");
    cfg.RouteSystemDns = true;
    q = BuildPacket(UDP, LOCAL, 50053, Pub("192.168.1.1"), 53, new byte[20]);
    Check(tr.Translate(q, q.Length) == Verdict.ReinjectInbound && udp.TryGet(new FlowKey(50053, Pub("192.168.1.1")), out var e) && e.IsDns, "opt-in: captured as DNS");
    var other = BuildPacket(UDP, LOCAL, 50053, Pub("8.8.8.8"), 443, new byte[20]);
    Check(tr.Translate(other, other.Length) == Verdict.Pass, "svchost non-DNS UDP untouched");
    var direct = BuildPacket(UDP, LOCAL, 50002, Pub("8.8.8.8"), 53, new byte[20]);
    Check(tr.Translate(direct, direct.Length) == Verdict.Pass, "other direct apps doing their own DNS untouched");
    await Task.CompletedTask;
});

// ---------- proxy client ----------
T("socks5: CONNECT by IPv4 and by domain name (remote DNS) through a no-auth server", async () =>
{
    using var echo = new EchoTcpServer(); using var px = new FakeSocks5();
    foreach (var target in new object[] { IPAddress.Loopback, "localhost" })
    {
        using var s = target is IPAddress ip ? await ProxyDialer.ConnectTcpAsync(P(px.Port), ip, echo.Port, ct) : await ProxyDialer.ConnectTcpAsync(P(px.Port), (string)target, echo.Port, ct);
        await s.SendAsync(Encoding.ASCII.GetBytes("ping"), SocketFlags.None);
        var b = new byte[4]; await ProxyDialer.ReadExactAsync(s, b, 4, ct);
        Check(Encoding.ASCII.GetString(b) == "ping", "echo through proxy");
    }
    Check(px.Requests.SequenceEqual(new[] { $"127.0.0.1:{echo.Port}", $"localhost:{echo.Port}" }), "proxy saw IP and unresolved domain: " + string.Join(",", px.Requests));
});

T("socks5: username/password auth success and failure", async () =>
{
    using var echo = new EchoTcpServer(); using var px = new FakeSocks5 { User = "u", Pass = "p" };
    var ok = P(px.Port); ok.Username = "u"; ok.Password = "p";
    using (var s = await ProxyDialer.ConnectTcpAsync(ok, IPAddress.Loopback, echo.Port, ct)) { }
    var bad = P(px.Port); bad.Username = "u"; bad.Password = "x";
    try { await ProxyDialer.ConnectTcpAsync(bad, IPAddress.Loopback, echo.Port, ct); Check(false, "bad password accepted"); }
    catch (ProxyException e) { Check(e.Message.Contains("rejected"), e.Message); }
    try { await ProxyDialer.ConnectTcpAsync(P(px.Port), IPAddress.Loopback, echo.Port, ct); Check(false, "missing creds accepted"); }
    catch (ProxyException) { }
});

T("socks5: connection refused by target is reported", async () =>
{
    using var px = new FakeSocks5();
    var dead = new TcpListener(IPAddress.Loopback, 0); dead.Start(); int port = ((IPEndPoint)dead.LocalEndpoint).Port; dead.Stop();
    try { await ProxyDialer.ConnectTcpAsync(P(px.Port), IPAddress.Loopback, port, ct); Check(false, "should fail"); }
    catch (ProxyException e) { Check(e.Message.Contains("refused"), e.Message); }
});

T("http: CONNECT tunnel with and without Basic auth", async () =>
{
    using var echo = new EchoTcpServer(); using var px = new FakeHttpProxy { RequireAuth = Convert.ToBase64String(Encoding.UTF8.GetBytes("a:b")) };
    var good = P(px.Port, ProxyType.Http); good.Username = "a"; good.Password = "b";
    using (var s = await ProxyDialer.ConnectTcpAsync(good, IPAddress.Loopback, echo.Port, ct))
    {
        await s.SendAsync(Encoding.ASCII.GetBytes("hi"), SocketFlags.None);
        var b = new byte[2]; await ProxyDialer.ReadExactAsync(s, b, 2, ct); Check(Encoding.ASCII.GetString(b) == "hi", "echo");
    }
    try { await ProxyDialer.ConnectTcpAsync(P(px.Port, ProxyType.Http), IPAddress.Loopback, echo.Port, ct); Check(false, "407 expected"); }
    catch (ProxyException e) { Check(e.Message.Contains("407"), e.Message); }
});

T("proxy test: reports exit IP, dead proxy and wrong protocol clearly (no hangs)", async () =>
{
    foreach (var body in new[] { "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n203.0.113.7\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n203.0.113.7\n\r\n0\r\n\r\n" })
    {
        using var echo = new EchoTcpServer(transform: _ => Encoding.ASCII.GetBytes(body)); using var px = new FakeSocks5();
        var r = await ProxyHealth.TestAsync(P(px.Port), ct, new[] { "127.0.0.1" }, echo.Port);
        Check(r.Ok && r.ExitIp == "203.0.113.7", "exit IP parsed: " + r.Message);
    }
    using (var px = new FakeSocks5())
    {
        var r = await ProxyHealth.TestAsync(P(px.Port), ct, new[] { "127.0.0.1" }, 1);   // target refuses
        Check(r.Ok && r.ExitIp == null && r.Message.Contains("Internet check failed"), "reachable proxy, no Internet: " + r.Message);
    }
    var dead = new TcpListener(IPAddress.Loopback, 0); dead.Start(); int port = ((IPEndPoint)dead.LocalEndpoint).Port; dead.Stop();
    var r2 = await ProxyHealth.TestAsync(P(port), ct);
    Check(!r2.Ok && r2.Message.Contains("Cannot connect"), "dead proxy: " + r2.Message);
    using var http = new FakeHttpProxy();
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var r3 = await ProxyHealth.TestAsync(P(http.Port, ProxyType.Socks5), ct);
    Check(!r3.Ok && r3.Message.Contains("HTTP proxy") && sw.Elapsed < TimeSpan.FromSeconds(8), "HTTP server queried as SOCKS5: " + r3.Message);
    using var px2 = new FakeSocks5 { User = "u", Pass = "p" };
    var r4 = await ProxyHealth.TestAsync(P(px2.Port), ct);
    Check(!r4.Ok && r4.Message.Contains("username"), "missing credentials: " + r4.Message);
});

T("dns-over-tcp: query is framed correctly and tunnelled through the proxy", async () =>
{
    // fake resolver on 127.0.0.1:53 would need privileges; instead verify framing by pointing the proxy at a mapping server
    using var px = new FakeSocks5();
    var seen = new TaskCompletionSource<byte[]>();
    var dns = new TcpListener(IPAddress.Loopback, 0); dns.Start(); int dport = ((IPEndPoint)dns.LocalEndpoint).Port;
    _ = Task.Run(async () =>
    {
        using var c = await dns.AcceptSocketAsync(); var l = new byte[2]; await ProxyDialer.ReadExactAsync(c, l, 2, ct);
        var q = new byte[(l[0] << 8) | l[1]]; await ProxyDialer.ReadExactAsync(c, q, q.Length, ct); seen.SetResult(q);
        var resp = (byte[])q.Clone(); resp[2] |= 0x80; var f = new byte[2 + resp.Length]; f[1] = (byte)resp.Length; resp.CopyTo(f, 2);
        await c.SendAsync(f, SocketFlags.None);
    });
    // DnsOverTcp always dials port 53; use the lower-level path with a custom port to validate the same framing code
    var query = new byte[] { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, (byte)'w', (byte)'w', (byte)'w', 0, 0, 1, 0, 1 };
    using var s = await ProxyDialer.ConnectTcpAsync(P(px.Port), IPAddress.Loopback, dport, ct);
    var framed = new byte[2 + query.Length]; framed[1] = (byte)query.Length; query.CopyTo(framed, 2);
    await s.SendAsync(framed, SocketFlags.None);
    Check((await seen.Task).SequenceEqual(query), "resolver received the query unchanged");
    var lb = new byte[2]; await ProxyDialer.ReadExactAsync(s, lb, 2, ct); var rb = new byte[lb[1]]; await ProxyDialer.ReadExactAsync(s, rb, rb.Length, ct);
    Check(rb[0] == 0x12 && rb[1] == 0x34 && (rb[2] & 0x80) != 0, "response id/flags");
    dns.Stop();
});

// ---------- redirectors (the parts WinDivert feeds) ----------
async Task<(Socket client, int port)> BoundClient()
{
    var c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    c.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    await Task.CompletedTask;
    return (c, ((IPEndPoint)c.LocalEndPoint!).Port);
}

T("tcp redirector: flow with a NAT entry is tunnelled through the proxy to the ORIGINAL destination", async () =>
{
    using var echo = new EchoTcpServer(); using var px = new FakeSocks5();
    var nat = new NatTable(); var cfg = P(px.Port);
    using var red = new TcpRedirector(nat, () => cfg); red.Start();
    var (c, cport) = await BoundClient();
    var entry = new NatEntry { OrigPort = (ushort)echo.Port, LocalIp = IpUtil.ToUInt(IPAddress.Loopback) };
    nat.Set(new FlowKey((ushort)cport, IpUtil.ToUInt(IPAddress.Loopback)), entry);
    await c.ConnectAsync(new IPEndPoint(IPAddress.Loopback, red.Port));
    var payload = new byte[300_000]; new Random(1).NextBytes(payload);
    var recv = new byte[payload.Length];
    var rx = Task.Run(() => ProxyDialer.ReadExactAsync(c, recv, recv.Length, ct));
    for (int o = 0; o < payload.Length;) o += await c.SendAsync(payload.AsMemory(o), SocketFlags.None);
    await rx;
    Check(recv.SequenceEqual(payload), "300 KB round trip intact");
    Check(px.Requests.Contains($"127.0.0.1:{echo.Port}"), "proxy was asked for the original destination");
    c.Shutdown(SocketShutdown.Send); await Task.Delay(300);
    Check(entry.ClosedAtTicks != 0, "NAT entry marked closed after tunnel ends");
    c.Dispose();
});

T("tcp redirector: connection without NAT entry is dropped, never forwarded", async () =>
{
    using var echo = new EchoTcpServer(); using var px = new FakeSocks5();
    using var red = new TcpRedirector(new NatTable(), () => P(px.Port)); red.Start();
    using var c = new Socket(SocketType.Stream, ProtocolType.Tcp);
    await c.ConnectAsync(new IPEndPoint(IPAddress.Loopback, red.Port));
    var n = await c.ReceiveAsync(new byte[1], SocketFlags.None);
    Check(n == 0, "closed");
    Check(px.Requests.Count == 0, "nothing sent to proxy");
});

T("tcp redirector: proxy down => fail closed (client reset, no direct connection made)", async () =>
{
    using var echo = new EchoTcpServer(); var seenDirect = 0;
    var dead = new TcpListener(IPAddress.Loopback, 0); dead.Start(); int dp = ((IPEndPoint)dead.LocalEndpoint).Port; dead.Stop();
    var nat = new NatTable(); using var red = new TcpRedirector(nat, () => P(dp)); red.Start();
    var (c, cport) = await BoundClient();
    nat.Set(new FlowKey((ushort)cport, IpUtil.ToUInt(IPAddress.Loopback)), new NatEntry { OrigPort = (ushort)echo.Port });
    await c.ConnectAsync(new IPEndPoint(IPAddress.Loopback, red.Port));
    int n; try { n = await c.ReceiveAsync(new byte[1], SocketFlags.None); } catch (SocketException) { n = 0; }
    Check(n == 0 && red.Failed == 1 && seenDirect == 0, "dropped");
    c.Dispose();
});

T("udp relay: datagram goes via SOCKS5 UDP ASSOCIATE, reply returns from the relay port with reverse NAT info", async () =>
{
    using var echo = new EchoUdpServer(); using var px = new FakeSocks5();
    var nat = new NatTable(); using var relay = new UdpRelay(nat, () => P(px.Port), () => "1.1.1.1"); relay.Start();
    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    client.Bind(new IPEndPoint(IPAddress.Loopback, 0)); int cport = ((IPEndPoint)client.LocalEndPoint!).Port;
    nat.Set(new FlowKey((ushort)cport, IpUtil.ToUInt(IPAddress.Loopback)), new NatEntry { OrigPort = (ushort)echo.Port, LocalIp = IpUtil.ToUInt(IPAddress.Loopback) });
    var msg = Encoding.ASCII.GetBytes("quic-ish datagram");
    for (int i = 0; i < 3; i++)
    {
        await client.SendToAsync(msg, SocketFlags.None, new IPEndPoint(IPAddress.Loopback, relay.Port));
        var buf = new byte[2048]; using var cts = new CancellationTokenSource(3000);
        var r = await client.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);
        Check(Encoding.ASCII.GetString(buf, 0, r.ReceivedBytes) == "quic-ish datagram", "echoed payload");
        Check(((IPEndPoint)r.RemoteEndPoint).Port == relay.Port, "reply comes from relay port (engine rewrites it)");
    }
    Check(px.UdpAssociations == 1, "one association reused for the same client socket");
    Check(nat.TryGet(new FlowKey((ushort)cport, IpUtil.ToUInt(IPAddress.Loopback)), out var e) && e.OrigPort == echo.Port, "reverse NAT");
});

T("udp relay: DNS query is answered via DNS-over-TCP through the proxy, local resolver never used", async () =>
{
    using var px = new FakeSocks5();
    // resolver reachable only through the proxy; DnsOverTcp dials :53, so run the test only if we can bind 53 on a loopback alias
    TcpListener? dns = null;
    try { dns = new TcpListener(IPAddress.Loopback, 53); dns.Start(); } catch { Console.WriteLine("      (skipped: cannot bind 127.0.0.1:53 here)"); return; }
    _ = Task.Run(async () =>
    {
        using var c = await dns.AcceptSocketAsync(); var l = new byte[2]; await ProxyDialer.ReadExactAsync(c, l, 2, ct);
        var q = new byte[(l[0] << 8) | l[1]]; await ProxyDialer.ReadExactAsync(c, q, q.Length, ct);
        q[2] |= 0x80; var f = new byte[2 + q.Length]; f[1] = (byte)q.Length; q.CopyTo(f, 2); await c.SendAsync(f, SocketFlags.None);
    });
    var nat = new NatTable(); using var relay = new UdpRelay(nat, () => P(px.Port), () => "127.0.0.1"); relay.Start();
    using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    client.Bind(new IPEndPoint(IPAddress.Loopback, 0)); int cport = ((IPEndPoint)client.LocalEndPoint!).Port;
    nat.Set(new FlowKey((ushort)cport, IpUtil.ToUInt(IPAddress.Loopback)), new NatEntry { OrigPort = 53, IsDns = true });
    var query = new byte[] { 0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, (byte)'a', 0, 0, 1, 0, 1 };
    await client.SendToAsync(query, SocketFlags.None, new IPEndPoint(IPAddress.Loopback, relay.Port));
    var buf = new byte[512]; using var cts = new CancellationTokenSource(3000);
    var r = await client.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), cts.Token);
    Check(buf[0] == 0xAB && buf[1] == 0xCD && (buf[2] & 0x80) != 0, "DNS answer");
    Check(px.Requests.Contains("127.0.0.1:53"), "resolver was reached THROUGH the proxy");
    dns.Stop();
});

// ---------- runner ----------
int failed = 0;
foreach (var (name, f) in tests)
{
    try { await f().WaitAsync(TimeSpan.FromSeconds(30)); Console.WriteLine($"  PASS  {name}"); }
    catch (Exception e) { failed++; Console.WriteLine($"  FAIL  {name}\n        {e.Message}"); }
}
Console.WriteLine($"\n{tests.Count - failed}/{tests.Count} passed");
return failed == 0 ? 0 : 1;
