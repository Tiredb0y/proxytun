using System.Runtime.InteropServices;
using System.Text;

namespace AppProxyManager.Engine;

internal static class NativeMethods
{
    // ---------- process image path ----------
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref uint size);

    public static string? GetProcessPath(int pid)
    {
        if (pid <= 4) return null;
        IntPtr h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, (uint)pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    // ---------- connection tables (iphlpapi) ----------
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] private static extern uint SetTcpEntry(ref MibTcpRow row);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort; }

    private static ushort Port(int raw) => (ushort)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
    private static uint Ip(int raw) { uint v = (uint)raw; return (v << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | (v >> 24); }

    private record struct TcpRow(int State, uint LocalIp, ushort LocalPort, uint RemoteIp, ushort RemotePort, int Pid, int RawLocalAddr, int RawLocalPort, int RawRemoteAddr, int RawRemotePort);

    private static List<TcpRow> TcpRows()
    {
        var rows = new List<TcpRow>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            size += 4096;
            IntPtr p = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedTcpTable(p, ref size, false, 2, 5, 0);
                if (r == 122) continue; // ERROR_INSUFFICIENT_BUFFER
                if (r != 0) return rows;
                int n = Marshal.ReadInt32(p);
                for (int i = 0; i < n; i++)
                {
                    int o = 4 + i * 24;
                    int la = Marshal.ReadInt32(p, o + 4), lp = Marshal.ReadInt32(p, o + 8), ra = Marshal.ReadInt32(p, o + 12), rp = Marshal.ReadInt32(p, o + 16);
                    rows.Add(new TcpRow(Marshal.ReadInt32(p, o), Ip(la), Port(lp), Ip(ra), Port(rp), Marshal.ReadInt32(p, o + 20), la, lp, ra, rp));
                }
                return rows;
            }
            finally { Marshal.FreeHGlobal(p); }
        }
        return rows;
    }

    private static List<(ushort Port, int Pid)> UdpRows()
    {
        var rows = new List<(ushort, int)>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1 /* UDP_TABLE_OWNER_PID */, 0);
        for (int attempt = 0; attempt < 5; attempt++)
        {
            size += 4096;
            IntPtr p = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedUdpTable(p, ref size, false, 2, 1, 0);
                if (r == 122) continue;
                if (r != 0) return rows;
                int n = Marshal.ReadInt32(p);
                for (int i = 0; i < n; i++)
                {
                    int o = 4 + i * 12;
                    rows.Add((Port(Marshal.ReadInt32(p, o + 4)), Marshal.ReadInt32(p, o + 8)));
                }
                return rows;
            }
            finally { Marshal.FreeHGlobal(p); }
        }
        return rows;
    }

    /// <summary>Authoritative owner lookup used when no WinDivert socket event was seen (sockets that predate the engine).</summary>
    public static int FallbackPid(byte proto, ushort localPort)
    {
        try
        {
            if (proto == 6)
            {
                var m = TcpRows().Where(r => r.LocalPort == localPort && r.State != 2).ToList();
                return m.Count > 0 ? m[0].Pid : 0;
            }
            foreach (var r in UdpRows()) if (r.Port == localPort) return r.Pid;
        }
        catch { }
        return 0;
    }

    public static int GetTcpListenerPid(int port)
    {
        try { foreach (var r in TcpRows()) if (r.State == 2 && r.LocalPort == port) return r.Pid; } catch { }
        return 0;
    }

    /// <summary>Resets established TCP connections of routed processes (needs administrator). Returns how many were reset.</summary>
    public static int ResetTcpConnections(Func<int, bool> isRouted, bool bypassLan)
    {
        int count = 0;
        foreach (var r in TcpRows())
        {
            if (r.State != 5 /* ESTABLISHED */ || r.Pid <= 4) continue;
            if (Core_IsLocal(r.RemoteIp, bypassLan) || !isRouted(r.Pid)) continue;
            var row = new MibTcpRow { State = 12 /* DELETE_TCB */, LocalAddr = (uint)r.RawLocalAddr, LocalPort = (uint)r.RawLocalPort, RemoteAddr = (uint)r.RawRemoteAddr, RemotePort = (uint)r.RawRemotePort };
            if (SetTcpEntry(ref row) == 0) count++;
        }
        return count;
    }

    private static bool Core_IsLocal(uint ip, bool bypassLan) =>
        AppProxyManager.Core.IpUtil.IsLoopback(ip) || (bypassLan && AppProxyManager.Core.IpUtil.IsLanOrSpecial(ip));

    // ---------- service pid (Dnscache) ----------
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr svc, int infoLevel, IntPtr buf, int size, out int needed);

    public static int GetServicePid(string serviceName)
    {
        IntPtr scm = OpenSCManager(null, null, 1);
        if (scm == IntPtr.Zero) return 0;
        try
        {
            IntPtr svc = OpenService(scm, serviceName, 4 /* SERVICE_QUERY_STATUS */);
            if (svc == IntPtr.Zero) return 0;
            try
            {
                IntPtr buf = Marshal.AllocHGlobal(64);
                try
                {
                    if (!QueryServiceStatusEx(svc, 0 /* SC_STATUS_PROCESS_INFO */, buf, 36, out _)) return 0;
                    return Marshal.ReadInt32(buf, 28); // dwProcessId
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
