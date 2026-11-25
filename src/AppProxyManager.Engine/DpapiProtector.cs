using System.Runtime.InteropServices;
using System.Text;
using AppProxyManager.Core;

namespace AppProxyManager.Engine;

/// <summary>Encrypts secrets with Windows DPAPI (current user scope): only this Windows account can decrypt them.</summary>
public sealed class DpapiProtector : ISecretProtector
{
    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int cbData; public IntPtr pbData; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob inp, string? descr, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob outp);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(ref DataBlob inp, IntPtr descr, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob outp);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr p);

    private const int UiForbidden = 1;

    public string Protect(string plain) => Convert.ToBase64String(Run(Encoding.UTF8.GetBytes(plain), true));

    public string? Unprotect(string protectedText)
    {
        try { return Encoding.UTF8.GetString(Run(Convert.FromBase64String(protectedText), false)); }
        catch { return null; } // different user / corrupted: treat as "no password stored"
    }

    private static byte[] Run(byte[] data, bool protect)
    {
        var inp = new DataBlob { cbData = data.Length, pbData = Marshal.AllocHGlobal(Math.Max(1, data.Length)) };
        Marshal.Copy(data, 0, inp.pbData, data.Length);
        try
        {
            DataBlob outp;
            bool ok = protect
                ? CryptProtectData(ref inp, "AppProxyManager", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outp)
                : CryptUnprotectData(ref inp, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, UiForbidden, out outp);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var result = new byte[outp.cbData];
            Marshal.Copy(outp.pbData, result, 0, outp.cbData);
            LocalFree(outp.pbData);
            return result;
        }
        finally { Marshal.FreeHGlobal(inp.pbData); }
    }
}
