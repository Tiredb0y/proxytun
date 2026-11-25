using System.Runtime.InteropServices;

namespace AppProxyManager.Engine;

internal enum WinDivertLayer { Network = 0, NetworkForward = 1, Flow = 2, Socket = 3, Reflect = 4 }

[Flags]
internal enum WinDivertFlags : ulong { None = 0, Sniff = 1, Drop = 2, RecvOnly = 4, SendOnly = 8 }

/// <summary>Mirror of WINDIVERT_ADDRESS (WinDivert 2.2, 80 bytes).</summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    [FieldOffset(8)] public uint Flags;          // Layer:8 Event:8 Sniffed Outbound Loopback Impostor IPv6 IPChecksum TCPChecksum UDPChecksum Reserved:8
    [FieldOffset(12)] public uint Reserved2;
    // --- network layer view ---
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;
    // --- socket layer view (overlaps) ---
    [FieldOffset(16)] public ulong EndpointId;
    [FieldOffset(24)] public ulong ParentEndpointId;
    [FieldOffset(32)] public uint ProcessId;
    [FieldOffset(36)] public uint LocalAddr0;
    [FieldOffset(52)] public uint RemoteAddr0;
    [FieldOffset(68)] public ushort LocalPort;
    [FieldOffset(70)] public ushort RemotePort;
    [FieldOffset(72)] public byte Protocol;

    public byte Layer => (byte)(Flags & 0xFF);
    public byte Event => (byte)((Flags >> 8) & 0xFF);
    public bool Outbound
    {
        get => (Flags & (1u << 17)) != 0;
        set { if (value) Flags |= 1u << 17; else Flags &= ~(1u << 17); }
    }
}

internal static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";
    public static readonly IntPtr InvalidHandle = new(-1);

    // Socket-layer event ids
    public const byte EventSocketBind = 0, EventSocketConnect = 1, EventSocketListen = 2, EventSocketAccept = 3, EventSocketClose = 4;

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr WinDivertOpen([MarshalAs(UnmanagedType.LPStr)] string filter, int layer, short priority, ulong flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(IntPtr handle, [Out] byte[] packet, uint packetLen, out uint recvLen, ref WinDivertAddress addr);

    /// <summary>Overload for the SOCKET layer, which delivers events (addresses) without packet data.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true, EntryPoint = "WinDivertRecv")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecvEvent(IntPtr handle, IntPtr packet, uint packetLen, IntPtr recvLen, ref WinDivertAddress addr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint packetLen, out uint sendLen, ref WinDivertAddress addr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    /// <summary>Aborts pending and future Recv/Send calls (how: 1=recv, 2=send, 3=both) so reader threads exit cleanly before Close.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertShutdown(IntPtr handle, int how);
}
