using System.Text.Json;

namespace AppProxyManager.Core;

public interface ISecretProtector
{
    string Protect(string plain);
    string? Unprotect(string protectedText);
}

public sealed class ConfigStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private readonly ISecretProtector _protector;
    public string FilePath { get; }

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AppProxyManager");

    public ConfigStore(ISecretProtector protector, string? directory = null)
    {
        _protector = protector;
        var dir = directory ?? DefaultDirectory;
        Directory.CreateDirectory(dir);
        FilePath = Path.Combine(dir, "config.json");
    }

    public AppConfig Load()
    {
        if (!File.Exists(FilePath)) return new AppConfig();
        try
        {
            var cfg = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(FilePath), Json) ?? new AppConfig();
            if (!string.IsNullOrEmpty(cfg.Proxy.PasswordProtected))
                cfg.Proxy.Password = _protector.Unprotect(cfg.Proxy.PasswordProtected);
            // de-duplicate defensively (hand-edited files)
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            cfg.Apps = cfg.Apps.Where(a => !string.IsNullOrWhiteSpace(a.Path) && seen.Add(a.Path)).ToList();
            return cfg;
        }
        catch (JsonException)
        {
            // keep the broken file for inspection and start fresh
            File.Copy(FilePath, FilePath + ".corrupt", true);
            return new AppConfig();
        }
    }

    public void Save(AppConfig cfg)
    {
        cfg.Proxy.PasswordProtected = string.IsNullOrEmpty(cfg.Proxy.Password) ? null : _protector.Protect(cfg.Proxy.Password);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(cfg, Json));
        File.Move(tmp, FilePath, true);
    }
}
