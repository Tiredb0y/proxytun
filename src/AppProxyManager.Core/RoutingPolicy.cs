using System.Collections.Concurrent;

namespace AppProxyManager.Core;

/// <summary>Decides whether a process id belongs to a routed application (matched by full executable path).</summary>
public sealed class RoutingPolicy
{
    private readonly Func<int, string?> _pathOf;
    private readonly Func<long> _now;
    private const long TtlMs = 5000;
    private volatile HashSet<string> _routed = new(StringComparer.OrdinalIgnoreCase);
    private volatile HashSet<string> _excluded = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, (bool Routed, string? Path, long T)> _cache = new();

    public RoutingPolicy(Func<int, string?> pathOf, Func<long>? now = null)
    {
        _pathOf = pathOf;
        _now = now ?? (() => Environment.TickCount64);
    }

    /// <summary>Excluded paths (our own exe, the proxy program itself) always win: they can never be routed (loop guard).</summary>
    public void SetRules(IEnumerable<string> routed, IEnumerable<string> excluded)
    {
        _routed = new HashSet<string>(routed.Select(AppConfig.Normalize), StringComparer.OrdinalIgnoreCase);
        _excluded = new HashSet<string>(excluded.Select(AppConfig.Normalize), StringComparer.OrdinalIgnoreCase);
        _cache.Clear();
    }

    public bool HasRules => _routed.Count > 0;

    public bool IsRouted(int pid, out string? path)
    {
        long now = _now();
        if (_cache.TryGetValue(pid, out var c) && now - c.T < TtlMs) { path = c.Path; return c.Routed; }
        var raw = pid > 4 ? _pathOf(pid) : null;
        string? p = null;
        if (!string.IsNullOrWhiteSpace(raw)) { try { p = AppConfig.Normalize(raw); } catch { p = null; } }
        bool r = p != null && _routed.Contains(p) && !_excluded.Contains(p);
        _cache[pid] = (r, r ? p : null, now);
        path = r ? p : null;
        if (_cache.Count > 4096) _cache.Clear();
        return r;
    }
}

/// <summary>Maps (protocol, local port) to the owning process id, fed by WinDivert socket events with a table-lookup fallback.</summary>
public sealed class PidTable
{
    private sealed class Entry { public int Pid; public long T; public bool FromEvent; public long ClosedAt; }
    private readonly ConcurrentDictionary<(byte, ushort), Entry> _map = new();
    private readonly Func<byte, ushort, int> _fallback;
    private readonly Func<long> _now;
    private const long FallbackTtlMs = 15_000;

    public PidTable(Func<byte, ushort, int> fallback, Func<long>? now = null)
    {
        _fallback = fallback;
        _now = now ?? (() => Environment.TickCount64);
    }

    public void Observe(byte proto, ushort localPort, int pid, bool closed)
    {
        if (localPort == 0 || pid == 0) return;
        var k = (proto, localPort);
        if (closed)
        {
            if (_map.TryGetValue(k, out var e) && e.Pid == pid) e.ClosedAt = _now();
            return;
        }
        _map[k] = new Entry { Pid = pid, T = _now(), FromEvent = true };
    }

    /// <summary>Returns the owning pid, or 0 if unknown.</summary>
    public int Lookup(byte proto, ushort localPort)
    {
        var k = (proto, localPort);
        long now = _now();
        if (_map.TryGetValue(k, out var e) && (e.FromEvent || now - e.T < FallbackTtlMs)) return e.Pid;
        int pid = _fallback(proto, localPort);
        _map[k] = new Entry { Pid = pid, T = now, FromEvent = false };
        return pid;
    }

    public void Prune()
    {
        long now = _now();
        foreach (var kv in _map)
            if ((kv.Value.ClosedAt != 0 && now - kv.Value.ClosedAt > 60_000) || now - kv.Value.T > 3_600_000)
                _map.TryRemove(kv.Key, out _);
    }
}
