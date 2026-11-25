using System.Net;

namespace AppProxyManager.Core;

/// <summary>IPv4 helpers. Addresses are handled as host-order uint (a.b.c.d == a&lt;&lt;24|b&lt;&lt;16|c&lt;&lt;8|d).</summary>
public static class IpUtil
{
    public static uint ToUInt(IPAddress a)
    {
        var b = a.MapToIPv4().GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress ToAddress(uint v) =>
        new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    public static bool IsLoopback(uint ip) => (ip >> 24) == 127;

    /// <summary>Private, link-local, multicast, broadcast and unspecified addresses.</summary>
    public static bool IsLanOrSpecial(uint ip)
    {
        uint a = ip >> 24;
        if (a == 10 || a == 0 || a >= 224) return true;
        if (a == 192 && ((ip >> 16) & 0xFF) == 168) return true;
        if (a == 172 && ((ip >> 16) & 0xF0) == 16) return true;
        if (a == 169 && ((ip >> 16) & 0xFF) == 254) return true;
        return false;
    }
}
