using System.Buffers.Binary;

namespace AppProxyManager.Core;

public struct PacketInfo
{
    public bool Valid;
    public byte Protocol;
    public int IpHeaderLen, TotalLen;
    public uint SrcIp, DstIp;
    public ushort SrcPort, DstPort;
    public byte TcpFlags;
    public int L4Offset => IpHeaderLen;
    public bool IsSyn => Protocol == 6 && (TcpFlags & 0x12) == 0x02;
}

/// <summary>Parses and edits raw IPv4 TCP/UDP packets, recomputing all checksums from scratch.</summary>
public static class PacketRewriter
{
    public static PacketInfo ParseV4(byte[] b, int len)
    {
        var p = new PacketInfo();
        if (len < 28 || (b[0] >> 4) != 4) return p;
        int ihl = (b[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8) return p;
        bool fragment = (b[6] & 0x20) != 0 || (((b[6] & 0x1F) << 8) | b[7]) != 0;
        if (fragment) return p;
        int total = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(2, 2));
        if (total < ihl + 8 || total > len) return p;
        byte proto = b[9];
        if (proto == 6 && total < ihl + 20) return p;
        if (proto != 6 && proto != 17) return p;
        p.Protocol = proto; p.IpHeaderLen = ihl; p.TotalLen = total;
        p.SrcIp = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(12, 4));
        p.DstIp = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(16, 4));
        p.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(ihl, 2));
        p.DstPort = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(ihl + 2, 2));
        if (proto == 6) p.TcpFlags = b[ihl + 13];
        p.Valid = true;
        return p;
    }

    /// <summary>For IPv6: returns next-header and source/destination port when there are no extension headers.</summary>
    public static bool TryParseV6(byte[] b, int len, out byte proto, out ushort srcPort, out ushort dstPort)
    {
        proto = 0; srcPort = 0; dstPort = 0;
        if (len < 48 || (b[0] >> 4) != 6) return false;
        proto = b[6];
        if (proto != 6 && proto != 17) return false;
        srcPort = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(40, 2));
        dstPort = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(42, 2));
        return true;
    }

    public static void Rewrite(byte[] b, int len, uint? srcIp, ushort? srcPort, uint? dstIp, ushort? dstPort)
    {
        var p = ParseV4(b, len);
        if (!p.Valid) throw new ArgumentException("Not a rewritable IPv4 TCP/UDP packet.");
        if (srcIp is uint s) BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(12, 4), s);
        if (dstIp is uint d) BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16, 4), d);
        if (srcPort is ushort sp) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p.IpHeaderLen, 2), sp);
        if (dstPort is ushort dp) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p.IpHeaderLen + 2, 2), dp);
        RecalcChecksums(b, len);
    }

    public static void RecalcChecksums(byte[] b, int len)
    {
        var p = ParseV4(b, len);
        if (!p.Valid) return;
        // IP header
        b[10] = 0; b[11] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(10, 2), Fold(Sum(b.AsSpan(0, p.IpHeaderLen), 0)));
        // L4 (pseudo-header + segment)
        int l4 = p.IpHeaderLen, l4Len = p.TotalLen - l4;
        int csumOff = l4 + (p.Protocol == 6 ? 16 : 6);
        b[csumOff] = 0; b[csumOff + 1] = 0;
        uint sum = (p.SrcIp >> 16) + (p.SrcIp & 0xFFFF) + (p.DstIp >> 16) + (p.DstIp & 0xFFFF) + p.Protocol + (uint)l4Len;
        sum = Sum(b.AsSpan(l4, l4Len), sum);
        ushort c = Fold(sum);
        if (p.Protocol == 17 && c == 0) c = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(csumOff, 2), c);
    }

    private static uint Sum(ReadOnlySpan<byte> d, uint acc)
    {
        int i = 0;
        for (; i + 1 < d.Length; i += 2) acc += (uint)((d[i] << 8) | d[i + 1]);
        if (i < d.Length) acc += (uint)(d[i] << 8);
        return acc;
    }

    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }
}
