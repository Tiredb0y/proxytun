using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace AppProxyManager.Engine;

public static class Elevation
{
    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Starts a fresh elevated copy of this program (UAC prompt). Returns false if the user declined.</summary>
    public static bool RestartElevated(string arguments)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!, arguments) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Win32Exception) { return false; }
    }
}

/// <summary>"Launch at sign-in" is implemented as a Scheduled Task with highest privileges (the only way to start an elevated app at logon without a UAC prompt).</summary>
public static class StartupTask
{
    public const string TaskName = "App Proxy Manager";

    public static bool IsEnabled() => Run("schtasks.exe", $"/Query /TN \"{TaskName}\"", elevate: false) == 0;

    public static bool Set(bool enable)
    {
        string exe = Environment.ProcessPath!;
        string args = enable
            ? $"/Create /TN \"{TaskName}\" /TR \"\\\"{exe}\\\" --startup\" /SC ONLOGON /RL HIGHEST /F"
            : $"/Delete /TN \"{TaskName}\" /F";
        int code = Run("schtasks.exe", args, elevate: !Elevation.IsElevated());
        return code == 0;
    }

    private static int Run(string file, string args, bool elevate)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args) { CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
            if (elevate) { psi.UseShellExecute = true; psi.Verb = "runas"; }
            else { psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; }
            using var p = Process.Start(psi)!;
            p.WaitForExit(15000);
            return p.HasExited ? p.ExitCode : -1;
        }
        catch (Win32Exception) { return -1; }
    }
}

/// <summary>
/// Reflected packets reach the local redirector as inbound connections, so Windows Firewall needs an inbound allow rule for this
/// executable (otherwise it silently drops them). The rule is created on first start and removed by uninstall.bat.
/// </summary>
public static class FirewallRule
{
    public const string RuleName = "App Proxy Manager (local redirector)";

    public static void Ensure(string exePath)
    {
        if (Netsh($"advfirewall firewall show rule name=\"{RuleName}\"") == 0) return;
        Netsh($"advfirewall firewall add rule name=\"{RuleName}\" dir=in action=allow program=\"{exePath}\" enable=yes profile=any protocol=any");
    }

    public static void Remove() => Netsh($"advfirewall firewall delete rule name=\"{RuleName}\"");

    private static int Netsh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh.exe", args)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })!;
            p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return p.ExitCode;
        }
        catch { return -1; }
    }
}
