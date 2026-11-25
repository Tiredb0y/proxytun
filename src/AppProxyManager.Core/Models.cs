using System.Text.Json.Serialization;

namespace AppProxyManager.Core;

public enum ProxyType { Socks5, Http }

public sealed class ProxySettings
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 12334;
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ProxyType Type { get; set; } = ProxyType.Socks5;
    public string? Username { get; set; }
    /// <summary>Plain-text password, in memory only. Never serialized.</summary>
    [JsonIgnore] public string? Password { get; set; }
    /// <summary>Password encrypted with the OS secret protector (DPAPI on Windows).</summary>
    public string? PasswordProtected { get; set; }
    [JsonIgnore] public bool HasCredentials => !string.IsNullOrEmpty(Username);

    public ProxySettings Clone() => (ProxySettings)MemberwiseClone();
}

public sealed class AppRule
{
    public string Path { get; set; } = "";
    public bool Enabled { get; set; } = true;
    [JsonIgnore] public string FileName => System.IO.Path.GetFileName(Path);
    [JsonIgnore] public string DisplayName => System.IO.Path.GetFileNameWithoutExtension(Path);
}

public sealed class AppConfig
{
    public int Version { get; set; } = 1;
    public ProxySettings Proxy { get; set; } = new();
    public List<AppRule> Apps { get; set; } = new();

    /// <summary>Resolver used (over TCP, through the proxy) for DNS queries of routed apps.</summary>
    public string DnsServer { get; set; } = "1.1.1.1";
    /// <summary>Routed apps keep talking to LAN / link-local / multicast addresses directly.</summary>
    public bool BypassLan { get; set; } = true;
    /// <summary>Drop IPv6 TCP/UDP of routed apps so they fall back to IPv4 (prevents IPv6 leaks).</summary>
    public bool BlockIPv6ForRoutedApps { get; set; } = true;
    /// <summary>On Start, reset already-open TCP connections of routed apps so they reconnect through the proxy.</summary>
    public bool ResetExistingConnections { get; set; } = false;
    /// <summary>Opt-in: send ALL DNS queries of the Windows DNS Client service through the proxy (see README, "DNS").</summary>
    public bool RouteSystemDns { get; set; } = false;
    public bool StartMinimized { get; set; } = false;
    public bool LaunchAtLogon { get; set; } = false;
    public bool AutoStartRouting { get; set; } = false;

    public static string Normalize(string path) => System.IO.Path.GetFullPath(path.Trim().Trim('"'));

    public bool Contains(string path) =>
        Apps.Any(a => string.Equals(a.Path, Normalize(path), StringComparison.OrdinalIgnoreCase));

    /// <summary>Adds an application. Returns false if it is already present (duplicates are rejected).</summary>
    public bool AddApp(string path)
    {
        var full = Normalize(path);
        if (Contains(full)) return false;
        Apps.Add(new AppRule { Path = full });
        return true;
    }

    public bool RemoveApp(string path)
    {
        var full = Normalize(path);
        return Apps.RemoveAll(a => string.Equals(a.Path, full, StringComparison.OrdinalIgnoreCase)) > 0;
    }
}
