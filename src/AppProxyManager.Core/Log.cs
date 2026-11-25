namespace AppProxyManager.Core;

public interface ILog
{
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? ex = null);
}

public sealed class NullLog : ILog
{
    public static readonly NullLog Instance = new();
    public void Info(string message) { }
    public void Warn(string message) { }
    public void Error(string message, Exception? ex = null) { }
}

/// <summary>Writes to a rolling log file and raises <see cref="LineLogged"/> for the UI.</summary>
public sealed class FileLog : ILog
{
    private readonly string _path;
    private readonly object _lock = new();
    public event Action<string>? LineLogged;

    public FileLog(string path)
    {
        _path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
    }

    public void Info(string m) => Write("INFO ", m);
    public void Warn(string m) => Write("WARN ", m);
    public void Error(string m, Exception? ex = null) => Write("ERROR", ex == null ? m : $"{m}: {ex.GetType().Name}: {ex.Message}");

    private void Write(string level, string m)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {m}";
        try
        {
            lock (_lock)
            {
                if (File.Exists(_path) && new FileInfo(_path).Length > 2_000_000)
                    File.Move(_path, _path + ".old", true);
                File.AppendAllText(_path, line + Environment.NewLine);
            }
        }
        catch { /* logging must never crash the app */ }
        LineLogged?.Invoke(line);
    }
}
