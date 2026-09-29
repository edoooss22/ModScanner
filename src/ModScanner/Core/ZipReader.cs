using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace ModScanner.Core;

/// <summary>Запись центрального каталога zip плюс то, что удалось узнать из локального заголовка.</summary>
internal sealed class ZipEntry
{
    public int Index;
    public string Name = "";
    public string LocalName = "";
    public ushort Method;
    public ushort Flags;
    public ushort DosTime;
    public ushort DosDate;
    public uint Crc;
    public long CompressedSize;
    public long UncompressedSize;
    public long LocalHeaderOffset;
    public long DataOffset = -1;
    public ushort VersionMadeBy;
    public ushort VersionNeeded;
    public uint ExternalAttributes;
    public byte[] Extra = Array.Empty<byte>();
    public byte[] LocalExtra = Array.Empty<byte>();
    public string Comment = "";
    public bool IsDirectory => Name.EndsWith('/');
    public bool Encrypted => (Flags & 1) != 0;
    public bool LocalHeaderBroken;
    public bool LocalNameMismatch;
    public bool LocalSizeMismatch;
    public bool Duplicate;          // такое имя уже встречалось раньше в центральном каталоге

    public DateTime Timestamp
    {
        get
        {
            int y = 1980 + (DosDate >> 9), mo = (DosDate >> 5) & 15, d = DosDate & 31;
            int h = DosTime >> 11, mi = (DosTime >> 5) & 63, s = (DosTime & 31) * 2;
            try { return new DateTime(y, Math.Clamp(mo, 1, 12), Math.Clamp(d, 1, 28 + (mo == 2 ? 0 : 3)), Math.Min(h, 23), Math.Min(mi, 59), Math.Min(s, 59)); }
            catch { return new DateTime(1980, 1, 1); }
        }
    }

    public string TimestampKey => $"{DosDate:X4}{DosTime:X4}";
}

/// <summary>
/// Собственный разбор zip: центральный каталог целиком, локальные заголовки — по требованию.
/// Нужен, потому что стандартный ZipArchive скрывает дубликаты имён, расхождения заголовков
/// и «хвосты» за пределами архива — а это как раз следы ручной правки jar.
/// </summary>
internal sealed class ZipReader
{
    public readonly byte[] Data;
    public readonly List<ZipEntry> Entries = new();
    public readonly List<string> Anomalies = new();
    public long EocdOffset = -1;
    public long CentralDirOffset = -1;
    public long CentralDirSize;
    public long FirstLocalHeader = long.MaxValue;
    public long PrependedBytes;
    public long TrailingBytes;
    public bool Zip64;
    public string ArchiveComment = "";

    private readonly Dictionary<string, ZipEntry> _byName = new(StringComparer.Ordinal);

    public ZipReader(byte[] data)
    {
        Data = data;
        Parse();
    }

    public ZipEntry? Find(string name) => _byName.TryGetValue(name, out var e) ? e : null;

    /// <summary>Последняя запись с таким именем — именно её берёт java.util.zip (по хеш-таблице центрального каталога).</summary>
    public ZipEntry? FindEffective(string name)
    {
        ZipEntry? last = null;
        foreach (var e in Entries) if (e.Name == name) last = e;
        return last;
    }

    private void Parse()
    {
        long eocd = FindEocd();
        if (eocd < 0) { Anomalies.Add("Не найдена запись конца центрального каталога (EOCD): это не zip-архив или он повреждён"); return; }
        EocdOffset = eocd;
        var span = Data.AsSpan();
        int diskEntries = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)eocd + 8));
        long totalEntries = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)eocd + 10));
        long cdSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)eocd + 12));
        long cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)eocd + 16));
        int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)eocd + 20));
        if (eocd + 22 + commentLen < Data.Length)
            TrailingBytes = Data.Length - (eocd + 22 + commentLen);
        if (commentLen > 0 && eocd + 22 + commentLen <= Data.Length)
            ArchiveComment = Encoding.UTF8.GetString(Data, (int)eocd + 22, commentLen);

        // zip64
        if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF)
        {
            long loc = eocd - 20;
            if (loc >= 0 && BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)loc)) == 0x07064b50)
            {
                long eocd64 = (long)BinaryPrimitives.ReadUInt64LittleEndian(span.Slice((int)loc + 8));
                if (eocd64 >= 0 && eocd64 + 56 <= Data.Length && BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)eocd64)) == 0x06064b50)
                {
                    Zip64 = true;
                    totalEntries = (long)BinaryPrimitives.ReadUInt64LittleEndian(span.Slice((int)eocd64 + 32));
                    cdSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(span.Slice((int)eocd64 + 40));
                    cdOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(span.Slice((int)eocd64 + 48));
                }
            }
        }

        CentralDirOffset = cdOffset;
        CentralDirSize = cdSize;
        if (cdOffset < 0 || cdOffset >= Data.Length) { Anomalies.Add("Смещение центрального каталога указывает за пределы файла"); return; }

        long p = cdOffset;
        int idx = 0;
        while (p + 46 <= Data.Length && BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p)) == 0x02014b50)
        {
            var e = new ZipEntry { Index = idx++ };
            e.VersionMadeBy = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 4));
            e.VersionNeeded = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 6));
            e.Flags = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 8));
            e.Method = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 10));
            e.DosTime = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 12));
            e.DosDate = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 14));
            e.Crc = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p + 16));
            e.CompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p + 20));
            e.UncompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p + 24));
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 28));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 30));
            int cmtLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice((int)p + 32));
            e.ExternalAttributes = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p + 38));
            e.LocalHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice((int)p + 42));
            long q = p + 46;
            if (q + nameLen + extraLen + cmtLen > Data.Length) { Anomalies.Add($"Запись #{idx} центрального каталога обрезана"); break; }
            bool utf8 = (e.Flags & 0x800) != 0;
            e.Name = DecodeName(Data, (int)q, nameLen, utf8);
            e.Extra = span.Slice((int)q + nameLen, extraLen).ToArray();
            if (cmtLen > 0) e.Comment = Encoding.UTF8.GetString(Data, (int)q + nameLen + extraLen, cmtLen);
            ParseZip64Extra(e);
            if (_byName.ContainsKey(e.Name)) e.Duplicate = true; else _byName[e.Name] = e;
            Entries.Add(e);
            if (!e.IsDirectory) FirstLocalHeader = Math.Min(FirstLocalHeader, e.LocalHeaderOffset);
            p = q + nameLen + extraLen + cmtLen;
        }
        if (Entries.Count != totalEntries && totalEntries != 0xFFFF)
            Anomalies.Add($"В EOCD заявлено записей: {totalEntries}, разобрано: {Entries.Count}");
        if (FirstLocalHeader != long.MaxValue && FirstLocalHeader > 0) PrependedBytes = FirstLocalHeader;

        foreach (var e in Entries) ReadLocalHeader(e);
    }

    private static string DecodeName(byte[] d, int off, int len, bool utf8)
    {
        // java.util.zip читает имена как UTF-8 всегда (кроме явно заданной кодировки), поэтому и мы так
        try { return new UTF8Encoding(false, true).GetString(d, off, len); }
        catch { return Encoding.Latin1.GetString(d, off, len); }
    }

    private static void ParseZip64Extra(ZipEntry e)
    {
        var x = e.Extra;
        int i = 0;
        while (i + 4 <= x.Length)
        {
            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(x.AsSpan(i));
            ushort sz = BinaryPrimitives.ReadUInt16LittleEndian(x.AsSpan(i + 2));
            if (id == 0x0001 && i + 4 + sz <= x.Length)
            {
                int j = i + 4;
                if (e.UncompressedSize == 0xFFFFFFFF && j + 8 <= i + 4 + sz) { e.UncompressedSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(x.AsSpan(j)); j += 8; }
                if (e.CompressedSize == 0xFFFFFFFF && j + 8 <= i + 4 + sz) { e.CompressedSize = (long)BinaryPrimitives.ReadUInt64LittleEndian(x.AsSpan(j)); j += 8; }
                if (e.LocalHeaderOffset == 0xFFFFFFFF && j + 8 <= i + 4 + sz) { e.LocalHeaderOffset = (long)BinaryPrimitives.ReadUInt64LittleEndian(x.AsSpan(j)); j += 8; }
            }
            i += 4 + sz;
        }
    }

    private void ReadLocalHeader(ZipEntry e)
    {
        long o = e.LocalHeaderOffset;
        if (o < 0 || o + 30 > Data.Length || BinaryPrimitives.ReadUInt32LittleEndian(Data.AsSpan((int)o)) != 0x04034b50)
        { e.LocalHeaderBroken = true; return; }
        var s = Data.AsSpan((int)o);
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(6));
        ushort method = BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(8));
        uint csz = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(18));
        uint usz = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(22));
        int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(26));
        int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(28));
        if (o + 30 + nameLen + extraLen > Data.Length) { e.LocalHeaderBroken = true; return; }
        e.LocalName = DecodeName(Data, (int)o + 30, nameLen, (flags & 0x800) != 0);
        e.LocalExtra = s.Slice(30 + nameLen, extraLen).ToArray();
        e.DataOffset = o + 30 + nameLen + extraLen;
        if (e.LocalName != e.Name) e.LocalNameMismatch = true;
        // при флаге 3 (data descriptor) размеры в локальном заголовке нули — это штатно
        if ((flags & 8) == 0 && csz != 0xFFFFFFFF && (csz != e.CompressedSize || usz != e.UncompressedSize)) e.LocalSizeMismatch = true;
        if (method != e.Method) e.LocalSizeMismatch = true;
    }

    private long FindEocd()
    {
        long min = Math.Max(0, Data.Length - 22 - 65535 - 64);
        for (long i = Data.Length - 22; i >= min; i--)
        {
            if (Data[i] == 0x50 && Data[i + 1] == 0x4b && Data[i + 2] == 0x05 && Data[i + 3] == 0x06)
            {
                int cl = BinaryPrimitives.ReadUInt16LittleEndian(Data.AsSpan((int)i + 20));
                if (i + 22 + cl <= Data.Length) return i;
            }
        }
        return -1;
    }

    /// <summary>Содержимое записи; null — если метод сжатия не поддержан или данные битые.</summary>
    public byte[]? Read(ZipEntry e)
    {
        if (e.LocalHeaderBroken || e.DataOffset < 0 || e.Encrypted) return null;
        if (e.DataOffset + e.CompressedSize > Data.Length) return null;
        try
        {
            if (e.Method == 0)
                return Data.AsSpan((int)e.DataOffset, (int)e.CompressedSize).ToArray();
            if (e.Method == 8)
            {
                using var ms = new MemoryStream(Data, (int)e.DataOffset, (int)e.CompressedSize, false);
                using var ds = new DeflateStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream(e.UncompressedSize > 0 && e.UncompressedSize < int.MaxValue ? (int)e.UncompressedSize : 4096);
                ds.CopyTo(outMs);
                return outMs.ToArray();
            }
        }
        catch { }
        return null;
    }

    public byte[]? Read(string name)
    {
        var e = FindEffective(name);
        return e is null ? null : Read(e);
    }
}
