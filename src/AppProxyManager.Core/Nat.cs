using System.Collections.Concurrent;

namespace AppProxyManager.Core;

/// <summary>Identifies a redirected flow: client source port + the remote IPv4 address it was talking to.</summary>
public readonly record struct FlowKey(ushort Port, uint Ip);

public sealed class NatEntry
{
    /// <summary>Client's own local address (restored as destination of reply packets).</summary>
    public uint LocalIp;
    /// <summary>Original remote port (restored as source port of reply packets).</summary>
    public ushort OrigPort;
    public int Pid;
    public bool IsDns;
    public long LastTicks = Environment.TickCount64;
    public long ClosedAtTicks;
    public void Touch() => LastTicks = Environment.TickCount64;
    public void MarkClosed() => ClosedAtTicks = Environment.TickCount64;
}

public sealed class NatTable
{
    private readonly ConcurrentDictionary<FlowKey, NatEntry> _map = new();
    public int Count => _map.Count;

    public void Set(FlowKey k, NatEntry e) => _map[k] = e;

    public bool TryGet(FlowKey k, out NatEntry e)
    {
        if (_map.TryGetValue(k, out e!)) { e.Touch(); return true; }
        return false;
    }

    public void Remove(FlowKey k) => _map.TryRemove(k, out _);

    /// <summary>Drops entries idle for longer than <paramref name="idleMs"/> or closed more than 30 s ago.</summary>
    public int Prune(long idleMs, long? nowTicks = null)
    {
        long now = nowTicks ?? Environment.TickCount64;
        int n = 0;
        foreach (var kv in _map)
        {
            var e = kv.Value;
            if (now - e.LastTicks > idleMs || (e.ClosedAtTicks != 0 && now - e.ClosedAtTicks > 30_000))
                if (_map.TryRemove(kv.Key, out _)) n++;
        }
        return n;
    }
}
