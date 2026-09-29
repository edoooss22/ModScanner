using System.Buffers.Binary;
using System.Text;

namespace ModScanner.Core;

internal enum CpTag : byte
{
    Utf8 = 1, Integer = 3, Float = 4, Long = 5, Double = 6, Class = 7, String = 8,
    Fieldref = 9, Methodref = 10, InterfaceMethodref = 11, NameAndType = 12,
    MethodHandle = 15, MethodType = 16, Dynamic = 17, InvokeDynamic = 18, Module = 19, Package = 20,
}

internal struct CpEntry
{
    public CpTag Tag;
    public int A, B;        // индексы либо младшие 32 бита
    public long Raw;        // long/double битами
    public string? Str;     // Utf8
}

internal sealed class MemberRef
{
    public string Owner = "";     // внутреннее имя класса-владельца
    public string Name = "";
    public string Desc = "";
    public bool IsField;
    public bool IsInterface;
    public string Key => Owner + "." + Name + Desc;
    public override string ToString() => $"{Owner}.{Name}{Desc}";
}

internal sealed class AnnValue
{
    public char Tag;                     // B C D F I J S Z s e c @ [
    public string? Str;                  // s, e(const), c(class descr)
    public string? EnumType;
    public long Num;
    public Annotation? Nested;
    public List<AnnValue>? Array;

    public IEnumerable<string> Strings()
    {
        if (Tag == 's' && Str is not null) yield return Str;
        if (Tag == '[' && Array is not null) foreach (var a in Array) foreach (var s in a.Strings()) yield return s;
        if (Tag == '@' && Nested is not null) foreach (var s in Nested.AllStrings()) yield return s;
    }

    public IEnumerable<string> Classes()
    {
        if (Tag == 'c' && Str is not null) yield return Descriptors.ClassOfDescriptor(Str) ?? Str;
        if (Tag == '[' && Array is not null) foreach (var a in Array) foreach (var s in a.Classes()) yield return s;
        if (Tag == '@' && Nested is not null) foreach (var s in Nested.AllClasses()) yield return s;
    }

    public IEnumerable<Annotation> Annotations()
    {
        if (Tag == '@' && Nested is not null) yield return Nested;
        if (Tag == '[' && Array is not null) foreach (var a in Array) foreach (var n in a.Annotations()) yield return n;
    }
}

internal sealed class Annotation
{
    public string Type = "";             // дескриптор Lorg/...;
    public Dictionary<string, AnnValue> Values = new();
    public string TypeName => Descriptors.ClassOfDescriptor(Type) ?? Type;
    public IEnumerable<string> AllStrings() => Values.Values.SelectMany(v => v.Strings());
    public IEnumerable<string> AllClasses() => Values.Values.SelectMany(v => v.Classes());
    public AnnValue? Get(string k) => Values.TryGetValue(k, out var v) ? v : null;
}

internal struct Insn
{
    public int Pc;
    public byte Op;
    public int Operand;     // индекс пула констант, цель перехода (абсолютная) либо непосредственное значение
    public int Operand2;
    public int Len;
}

internal sealed class MethodInfo
{
    public int Access;
    public string Name = "";
    public string Desc = "";
    public byte[]? Code;
    public List<Insn> Insns = new();
    public int MaxStack, MaxLocals;
    public int ExceptionHandlers;
    public bool HasLineNumbers, HasLocalVars;
    public List<Annotation> Annotations = new();
    public List<string> Attributes = new();
    public string? Signature;
    public bool IsStatic => (Access & 0x0008) != 0;
    public bool IsNative => (Access & 0x0100) != 0;
    public bool IsAbstract => (Access & 0x0400) != 0;
    public bool IsSynthetic => (Access & 0x1000) != 0;
    public override string ToString() => Name + Desc;
}

internal sealed class FieldInfo
{
    public int Access;
    public string Name = "";
    public string Desc = "";
    public string? Signature;
    public List<Annotation> Annotations = new();
    public bool IsStatic => (Access & 0x0008) != 0;
    public bool IsFinal => (Access & 0x0010) != 0;
}

/// <summary>Разбор файла класса Java: пул констант, члены, атрибуты, байт-код методов, аннотации.</summary>
internal sealed class ClassFile
{
    public string Name = "";
    public string? Super;
    public string[] Interfaces = Array.Empty<string>();
    public int Access;
    public int Major, Minor;
    public CpEntry[] Cp = Array.Empty<CpEntry>();
    public List<FieldInfo> Fields = new();
    public List<MethodInfo> Methods = new();
    public List<Annotation> Annotations = new();
    public List<(int Kind, string Owner, string Name, string Desc, List<string> Args)> Bootstraps = new();
    // по каждому bootstrap-методу: ссылки на члены из его аргументов-MethodHandle (лямбды, ссылки на методы вида X::send)
    public List<List<MemberRef>> BootstrapHandles = new();
    public List<string> InnerClasses = new();
    public List<string> Attributes = new();
    public string? SourceFile;
    public string? OuterClass;
    public string? NestHost;
    public string? Signature;
    public bool ParseError;
    public string? ParseErrorText;
    public int Size;

    // производное
    public readonly HashSet<string> RefClasses = new(StringComparer.Ordinal);
    public readonly List<MemberRef> RefMembers = new();
    public readonly List<string> Strings = new();
    public readonly List<int> IntConstants = new();
    public readonly List<long> LongConstants = new();
    public readonly List<double> DoubleConstants = new();

    public bool IsInterface => (Access & 0x0200) != 0;
    public bool IsAbstract => (Access & 0x0400) != 0;
    public bool IsSynthetic => (Access & 0x1000) != 0;
    public bool IsEnum => (Access & 0x4000) != 0;
    public bool IsRecordLike => Super == "java/lang/Record";
    public string SimpleName => Name[(Name.LastIndexOf('/') + 1)..];
    public string Package => Name.Contains('/') ? Name[..Name.LastIndexOf('/')] : "";
    public string OuterName { get { int i = Name.IndexOf('$'); return i > 0 ? Name[..i] : Name; } }

    public static ClassFile Parse(byte[] data)
    {
        var cf = new ClassFile { Size = data.Length };
        try { cf.ParseInner(data); }
        catch (Exception ex) { cf.ParseError = true; cf.ParseErrorText = ex.Message; }
        return cf;
    }

    // --------------------------------------------------------------- пул констант

    public string Utf8(int i) => i > 0 && i < Cp.Length && Cp[i].Tag == CpTag.Utf8 ? Cp[i].Str ?? "" : "";
    public string ClassName(int i) => i > 0 && i < Cp.Length && Cp[i].Tag == CpTag.Class ? Utf8(Cp[i].A) : "";
    public CpTag TagAt(int i) => i > 0 && i < Cp.Length ? Cp[i].Tag : 0;

    public MemberRef? Member(int i)
    {
        if (i <= 0 || i >= Cp.Length) return null;
        var e = Cp[i];
        if (e.Tag is not (CpTag.Fieldref or CpTag.Methodref or CpTag.InterfaceMethodref)) return null;
        if (e.B <= 0 || e.B >= Cp.Length || Cp[e.B].Tag != CpTag.NameAndType) return null;
        var nt = Cp[e.B];
        return new MemberRef
        {
            Owner = ClassName(e.A), Name = Utf8(nt.A), Desc = Utf8(nt.B),
            IsField = e.Tag == CpTag.Fieldref, IsInterface = e.Tag == CpTag.InterfaceMethodref,
        };
    }

    /// <summary>Что за константа стоит за ldc/ldc_w/ldc2_w: int/long/float/double/String/Class/иное.</summary>
    public string LdcKind(int i)
    {
        return TagAt(i) switch
        {
            CpTag.Integer => "int", CpTag.Long => "long", CpTag.Float => "float", CpTag.Double => "double",
            CpTag.String => "string", CpTag.Class => "class", CpTag.MethodHandle => "mh", CpTag.MethodType => "mt",
            CpTag.Dynamic => "dyn", _ => "?",
        };
    }

    /// <summary>Члены, на которые ссылается invokedynamic (аргументы-MethodHandle его bootstrap и сам bootstrap).</summary>
    public IReadOnlyList<MemberRef> IndyRefs(int indyCp)
    {
        if (TagAt(indyCp) != CpTag.InvokeDynamic) return Array.Empty<MemberRef>();
        int bsm = Cp[indyCp].A;
        return bsm >= 0 && bsm < BootstrapHandles.Count ? BootstrapHandles[bsm] : Array.Empty<MemberRef>();
    }

    /// <summary>Имя вызова invokedynamic (makeConcatWithConstants, apply, run…).</summary>
    public string IndyName(int indyCp)
    {
        if (TagAt(indyCp) != CpTag.InvokeDynamic) return "";
        int nt = Cp[indyCp].B;
        return nt > 0 && nt < Cp.Length && Cp[nt].Tag == CpTag.NameAndType ? Utf8(Cp[nt].A) : "";
    }

    public double LdcDouble(int i) => TagAt(i) switch
    {
        CpTag.Double => BitConverter.Int64BitsToDouble(Cp[i].Raw),
        CpTag.Float => BitConverter.Int32BitsToSingle((int)Cp[i].Raw),
        CpTag.Integer or CpTag.Long => Cp[i].Raw,
        _ => double.NaN,
    };

    public long LdcInt(int i) => TagAt(i) is CpTag.Integer or CpTag.Long ? Cp[i].Raw : 0;
    public string? LdcString(int i) => TagAt(i) == CpTag.String ? Utf8(Cp[i].A) : null;

    private void ParseInner(byte[] d)
    {
        var r = new Reader(d);
        if (r.U4() != 0xCAFEBABE) throw new Exception("нет магического числа CAFEBABE");
        Minor = r.U2(); Major = r.U2();
        int n = r.U2();
        Cp = new CpEntry[n];
        for (int i = 1; i < n; i++)
        {
            var tag = (CpTag)r.U1();
            var e = new CpEntry { Tag = tag };
            switch (tag)
            {
                case CpTag.Utf8: { int len = r.U2(); e.Str = JavaUtf8.Decode(d, r.Pos, len); r.Pos += len; break; }
                case CpTag.Integer: e.Raw = (int)r.U4(); break;
                case CpTag.Float: e.Raw = (int)r.U4(); break;
                case CpTag.Long: e.Raw = (long)r.U8(); break;
                case CpTag.Double: e.Raw = (long)r.U8(); break;
                case CpTag.Class: case CpTag.String: case CpTag.MethodType: case CpTag.Module: case CpTag.Package:
                    e.A = r.U2(); break;
                case CpTag.Fieldref: case CpTag.Methodref: case CpTag.InterfaceMethodref: case CpTag.NameAndType:
                case CpTag.Dynamic: case CpTag.InvokeDynamic:
                    e.A = r.U2(); e.B = r.U2(); break;
                case CpTag.MethodHandle: e.A = r.U1(); e.B = r.U2(); break;
                default: throw new Exception($"неизвестный тег пула констант {(int)tag} в #{i}");
            }
            Cp[i] = e;
            if (tag is CpTag.Long or CpTag.Double) { i++; }
        }
        Access = r.U2();
        Name = ClassName(r.U2());
        int sup = r.U2();
        Super = sup == 0 ? null : ClassName(sup);
        int ic = r.U2();
        Interfaces = new string[ic];
        for (int i = 0; i < ic; i++) Interfaces[i] = ClassName(r.U2());

        int fc = r.U2();
        for (int i = 0; i < fc; i++)
        {
            var f = new FieldInfo { Access = r.U2(), Name = Utf8(r.U2()), Desc = Utf8(r.U2()) };
            int ac = r.U2();
            for (int a = 0; a < ac; a++)
            {
                string an = Utf8(r.U2()); int alen = (int)r.U4(); int end = r.Pos + alen;
                if (an is "RuntimeVisibleAnnotations" or "RuntimeInvisibleAnnotations") f.Annotations.AddRange(ReadAnnotations(r));
                else if (an == "Signature") f.Signature = Utf8(r.U2());
                r.Pos = end;
            }
            Fields.Add(f);
        }
        int mc = r.U2();
        for (int i = 0; i < mc; i++)
        {
            var m = new MethodInfo { Access = r.U2(), Name = Utf8(r.U2()), Desc = Utf8(r.U2()) };
            int ac = r.U2();
            for (int a = 0; a < ac; a++)
            {
                string an = Utf8(r.U2()); int alen = (int)r.U4(); int end = r.Pos + alen;
                m.Attributes.Add(an);
                if (an == "Code") ReadCode(r, m, end);
                else if (an is "RuntimeVisibleAnnotations" or "RuntimeInvisibleAnnotations") m.Annotations.AddRange(ReadAnnotations(r));
                else if (an == "Signature") m.Signature = Utf8(r.U2());
                r.Pos = end;
            }
            Methods.Add(m);
        }
        int cac = r.U2();
        for (int a = 0; a < cac; a++)
        {
            string an = Utf8(r.U2()); int alen = (int)r.U4(); int end = r.Pos + alen;
            Attributes.Add(an);
            switch (an)
            {
                case "SourceFile": SourceFile = Utf8(r.U2()); break;
                case "Signature": Signature = Utf8(r.U2()); break;
                case "NestHost": NestHost = ClassName(r.U2()); break;
                case "InnerClasses":
                {
                    int nc = r.U2();
                    for (int i = 0; i < nc; i++) { int inner = r.U2(); r.U2(); r.U2(); r.U2(); string icn = ClassName(inner); if (icn.Length > 0) InnerClasses.Add(icn); }
                    break;
                }
                case "EnclosingMethod": OuterClass = ClassName(r.U2()); break;
                case "RuntimeVisibleAnnotations": case "RuntimeInvisibleAnnotations": Annotations.AddRange(ReadAnnotations(r)); break;
                case "BootstrapMethods":
                {
                    int bc = r.U2();
                    for (int i = 0; i < bc; i++)
                    {
                        int mh = r.U2(); int argc = r.U2();
                        var args = new List<string>();
                        var handles = new List<MemberRef>();
                        for (int k = 0; k < argc; k++)
                        {
                            int ai = r.U2();
                            args.Add(DescribeConst(ai));
                            if (TagAt(ai) == CpTag.MethodHandle) { var hr = Member(Cp[ai].B); if (hr is not null) handles.Add(hr); }
                        }
                        int kind = 0; string owner = "", name = "", desc = "";
                        if (TagAt(mh) == CpTag.MethodHandle)
                        {
                            kind = Cp[mh].A;
                            var mr = Member(Cp[mh].B);
                            if (mr is not null) { owner = mr.Owner; name = mr.Name; desc = mr.Desc; }
                        }
                        Bootstraps.Add((kind, owner, name, desc, args));
                        if (owner.Length > 0) handles.Add(new MemberRef { Owner = owner, Name = name, Desc = desc });
                        BootstrapHandles.Add(handles);
                    }
                    break;
                }
            }
            r.Pos = end;
        }

        Derive();
    }

    private string DescribeConst(int i)
    {
        return TagAt(i) switch
        {
            CpTag.String => "\"" + Utf8(Cp[i].A) + "\"",
            CpTag.Class => ClassName(i),
            CpTag.Integer => Cp[i].Raw.ToString(),
            CpTag.Long => Cp[i].Raw + "L",
            CpTag.MethodHandle => Member(Cp[i].B)?.ToString() ?? "mh",
            CpTag.MethodType => Utf8(Cp[i].A),
            _ => "?",
        };
    }

    private void ReadCode(Reader r, MethodInfo m, int end)
    {
        m.MaxStack = r.U2(); m.MaxLocals = r.U2();
        int clen = (int)r.U4();
        if (clen < 0 || r.Pos + clen > end) throw new Exception("длина кода за пределами атрибута");
        m.Code = new byte[clen];
        Array.Copy(r.Data, r.Pos, m.Code, 0, clen);
        r.Pos += clen;
        m.ExceptionHandlers = r.U2();
        r.Pos += m.ExceptionHandlers * 8;
        int ac = r.U2();
        for (int a = 0; a < ac; a++)
        {
            string an = Utf8(r.U2()); int alen = (int)r.U4();
            if (an == "LineNumberTable") m.HasLineNumbers = true;
            else if (an is "LocalVariableTable" or "LocalVariableTypeTable") m.HasLocalVars = true;
            r.Pos += alen;
        }
        m.Insns = Bytecode.Disassemble(m.Code);
    }

    private List<Annotation> ReadAnnotations(Reader r)
    {
        var list = new List<Annotation>();
        int n = r.U2();
        for (int i = 0; i < n; i++) list.Add(ReadAnnotation(r));
        return list;
    }

    private Annotation ReadAnnotation(Reader r)
    {
        var a = new Annotation { Type = Utf8(r.U2()) };
        int n = r.U2();
        for (int i = 0; i < n; i++)
        {
            string k = Utf8(r.U2());
            a.Values[k] = ReadAnnValue(r);
        }
        return a;
    }

    private AnnValue ReadAnnValue(Reader r)
    {
        char tag = (char)r.U1();
        var v = new AnnValue { Tag = tag };
        switch (tag)
        {
            case 'B': case 'C': case 'I': case 'S': case 'Z': case 'F': case 'D': case 'J':
            { int ci = r.U2(); v.Num = TagAt(ci) is CpTag.Integer or CpTag.Long or CpTag.Float or CpTag.Double ? Cp[ci].Raw : 0; break; }
            case 's': v.Str = Utf8(r.U2()); break;
            case 'e': v.EnumType = Utf8(r.U2()); v.Str = Utf8(r.U2()); break;
            case 'c': v.Str = Utf8(r.U2()); break;
            case '@': v.Nested = ReadAnnotation(r); break;
            case '[':
            {
                int n = r.U2();
                v.Array = new List<AnnValue>(n);
                for (int i = 0; i < n; i++) v.Array.Add(ReadAnnValue(r));
                break;
            }
            default: throw new Exception($"неизвестный тег значения аннотации '{tag}'");
        }
        return v;
    }

    private void Derive()
    {
        for (int i = 1; i < Cp.Length; i++)
        {
            var e = Cp[i];
            switch (e.Tag)
            {
                case CpTag.Class:
                {
                    string c = Utf8(e.A);
                    if (c.StartsWith('[')) { var el = Descriptors.ClassOfDescriptor(c); if (el is not null) RefClasses.Add(el); }
                    else RefClasses.Add(c);
                    break;
                }
                case CpTag.Fieldref: case CpTag.Methodref: case CpTag.InterfaceMethodref:
                {
                    var m = Member(i);
                    if (m is not null) { RefMembers.Add(m); foreach (var c in Descriptors.ClassesIn(m.Desc)) RefClasses.Add(c); }
                    break;
                }
                case CpTag.String: Strings.Add(Utf8(e.A)); break;
                case CpTag.Integer: IntConstants.Add((int)e.Raw); break;
                case CpTag.Long: LongConstants.Add(e.Raw); break;
                case CpTag.Double: DoubleConstants.Add(BitConverter.Int64BitsToDouble(e.Raw)); break;
                case CpTag.NameAndType: foreach (var c in Descriptors.ClassesIn(Utf8(e.B))) RefClasses.Add(c); break;
                case CpTag.MethodType: foreach (var c in Descriptors.ClassesIn(Utf8(e.A))) RefClasses.Add(c); break;
            }
        }
        foreach (var f in Fields) foreach (var c in Descriptors.ClassesIn(f.Desc)) RefClasses.Add(c);
        foreach (var m in Methods) foreach (var c in Descriptors.ClassesIn(m.Desc)) RefClasses.Add(c);
        foreach (var a in Annotations) { RefClasses.Add(a.TypeName); foreach (var c in a.AllClasses()) RefClasses.Add(c); }
        foreach (var m in Methods) foreach (var a in m.Annotations) { RefClasses.Add(a.TypeName); foreach (var c in a.AllClasses()) RefClasses.Add(c); }
        foreach (var f in Fields) foreach (var a in f.Annotations) { RefClasses.Add(a.TypeName); foreach (var c in a.AllClasses()) RefClasses.Add(c); }
        if (Super is not null) RefClasses.Add(Super);
        foreach (var i in Interfaces) RefClasses.Add(i);
        RefClasses.Remove(Name);
    }

    private sealed class Reader
    {
        public readonly byte[] Data;
        public int Pos;
        public Reader(byte[] d) { Data = d; }
        public int U1() { if (Pos + 1 > Data.Length) throw new Exception("обрыв файла класса"); return Data[Pos++]; }
        public int U2() { if (Pos + 2 > Data.Length) throw new Exception("обрыв файла класса"); int v = BinaryPrimitives.ReadUInt16BigEndian(Data.AsSpan(Pos)); Pos += 2; return v; }
        public uint U4() { if (Pos + 4 > Data.Length) throw new Exception("обрыв файла класса"); uint v = BinaryPrimitives.ReadUInt32BigEndian(Data.AsSpan(Pos)); Pos += 4; return v; }
        public ulong U8() { if (Pos + 8 > Data.Length) throw new Exception("обрыв файла класса"); ulong v = BinaryPrimitives.ReadUInt64BigEndian(Data.AsSpan(Pos)); Pos += 8; return v; }
    }
}

/// <summary>«Изменённый UTF-8» Java: нулевой символ как C0 80, суррогаты как две трёхбайтовые последовательности.</summary>
internal static class JavaUtf8
{
    public static string Decode(byte[] d, int off, int len)
    {
        var sb = new StringBuilder(len);
        int i = off, end = off + len;
        while (i < end)
        {
            int b = d[i];
            if (b < 0x80) { sb.Append((char)b); i++; }
            else if ((b & 0xE0) == 0xC0 && i + 1 < end) { sb.Append((char)(((b & 0x1F) << 6) | (d[i + 1] & 0x3F))); i += 2; }
            else if ((b & 0xF0) == 0xE0 && i + 2 < end) { sb.Append((char)(((b & 0x0F) << 12) | ((d[i + 1] & 0x3F) << 6) | (d[i + 2] & 0x3F))); i += 3; }
            else { sb.Append('�'); i++; }
        }
        return sb.ToString();
    }
}

internal static class Descriptors
{
    /// <summary>Все имена классов в дескрипторе поля/метода/сигнатуре.</summary>
    public static IEnumerable<string> ClassesIn(string desc)
    {
        int i = 0;
        while (i < desc.Length)
        {
            if (desc[i] == 'L')
            {
                int j = desc.IndexOf(';', i);
                if (j < 0) yield break;
                string c = desc[(i + 1)..j];
                int lt = c.IndexOf('<');
                if (lt >= 0) c = c[..lt];
                yield return c;
                i = j + 1;
            }
            else i++;
        }
    }

    /// <summary>Класс из дескриптора вида Lfoo/Bar; либо [[Lfoo/Bar; — иначе null.</summary>
    public static string? ClassOfDescriptor(string d)
    {
        int i = 0;
        while (i < d.Length && d[i] == '[') i++;
        if (i < d.Length && d[i] == 'L' && d.EndsWith(';')) return d[(i + 1)..^1];
        return null;
    }

    public static string Pretty(string internalName) => internalName.Replace('/', '.');

    /// <summary>Читаемая форма дескриптора метода: (int, String) → boolean.</summary>
    public static string PrettyMethodDesc(string desc, Func<string, string>? classMap = null)
    {
        int close = desc.IndexOf(')');
        if (!desc.StartsWith('(') || close < 0) return desc;
        var args = new List<string>();
        int i = 1;
        while (i < close) args.Add(ReadType(desc, ref i, classMap));
        int j = close + 1;
        string ret = j < desc.Length ? ReadType(desc, ref j, classMap) : "?";
        return "(" + string.Join(", ", args) + ") → " + ret;
    }

    private static string ReadType(string d, ref int i, Func<string, string>? classMap)
    {
        int dims = 0;
        while (i < d.Length && d[i] == '[') { dims++; i++; }
        string t;
        if (i >= d.Length) return "?";
        switch (d[i])
        {
            case 'L':
            {
                int j = d.IndexOf(';', i);
                string c = j < 0 ? d[(i + 1)..] : d[(i + 1)..j];
                i = j < 0 ? d.Length : j + 1;
                if (classMap is not null) c = classMap(c);
                t = c[(c.LastIndexOf('/') + 1)..];
                break;
            }
            case 'I': t = "int"; i++; break;
            case 'J': t = "long"; i++; break;
            case 'Z': t = "boolean"; i++; break;
            case 'F': t = "float"; i++; break;
            case 'D': t = "double"; i++; break;
            case 'B': t = "byte"; i++; break;
            case 'C': t = "char"; i++; break;
            case 'S': t = "short"; i++; break;
            case 'V': t = "void"; i++; break;
            default: t = d[i].ToString(); i++; break;
        }
        return t + new string('[', dims).Replace("[", "[]");
    }
}
