using System.Buffers.Binary;
using System.Text;

namespace ModScanner.Core;

/// <summary>
/// Расшифровка строк эмуляцией байт-кода. Обфускаторы прячут строки (адреса серверов, названия модулей,
/// команды) за вызовом «расшифровщика»: массив чисел → char[] → String, XOR с ключом, таблица строк,
/// заполняемая в &lt;clinit&gt;. Эмулятор исполняет только безопасное подмножество JVM: арифметику,
/// массивы, String/StringBuilder/Base64 и собственные статические методы мода — без сети, файлов,
/// рефлексии и кода игры. Любая неподдерживаемая операция даёт «неизвестно»; число шагов ограничено.
///
/// Два режима:
///   * конкретный — ветвления исполняются по-настоящему (расшифровщик, &lt;clinit&gt;);
///   * линейный — обход метода подряд без переходов: так находятся места вызова расшифровщика
///     с константными аргументами (массив, собранный из bipush/iastore, строка + ключ).
/// </summary>
internal sealed class StringEmu
{
    private sealed class Unknown { public static readonly Unknown V = new(); public override string ToString() => "?"; }
    private sealed class NewObj { public string Cls = ""; public object? Value; }
    private sealed class Marker { public string Kind = ""; }
    private sealed class AbortException : Exception { public AbortException(string m) : base(m) { } }

    private readonly Func<string, string, string, MethodInfo?> _findStatic;   // owner, name, desc → метод мода
    private readonly Func<string, bool> _isOwn;
    private readonly Dictionary<string, object?> _statics = new(StringComparer.Ordinal);   // owner.name → значение
    private readonly Dictionary<string, (MethodInfo M, Dictionary<int, int> Index)> _prepared = new();
    private long _budget;
    private readonly System.Diagnostics.Stopwatch _clock = System.Diagnostics.Stopwatch.StartNew();
    private readonly TimeSpan _timeLimit;

    public StringEmu(Func<string, string, string, MethodInfo?> findStatic, Func<string, bool> isOwn, TimeSpan timeLimit)
    {
        _findStatic = findStatic; _isOwn = isOwn; _timeLimit = timeLimit;
    }

    public bool TimeUp => _clock.Elapsed > _timeLimit;
    private static readonly bool Debug = Environment.GetEnvironmentVariable("MS_EMU_DEBUG") == "1";
    private static void Dbg(string where, Exception ex) { if (Debug) Console.WriteLine($"   [emu] {where}: {ex.Message}"); }

    // ------------------------------------------------------------------ публичное

    /// <summary>Исполнить &lt;clinit&gt; класса: заполняет статические поля (таблицы строк). Возвращает строки из полей.</summary>
    public List<string> RunClinit(string owner, MethodInfo clinit)
    {
        var res = new List<string>();
        if (TimeUp || clinit.Code is null) return res;
        _budget = 400_000;
        try { Exec(owner, clinit, Array.Empty<object?>(), concrete: true, depth: 0, collect: null); }
        catch (Exception ex) { Dbg(owner + ".<clinit>", ex); }
        if (Debug) Console.WriteLine($"   [emu] {owner}.<clinit>: статиков {_statics.Count}, бюджет {_budget}: " + string.Join("; ", _statics.Select(kv => kv.Key + "=" + (kv.Value is string sv ? sv : kv.Value?.GetType().Name ?? "null"))));
        foreach (var (k, v) in _statics)
        {
            if (!k.StartsWith(owner + ".", StringComparison.Ordinal)) continue;
            if (v is string s && Printable(s)) res.Add(s);
            else if (v is object?[] arr) foreach (var x in arr) if (x is string xs && Printable(xs)) res.Add(xs);
        }
        return res;
    }

    /// <summary>Линейный проход метода: строки, которые он собирает/расшифровывает из констант.</summary>
    public List<string> Scan(string owner, MethodInfo m)
    {
        var res = new List<string>();
        if (TimeUp || m.Code is null || m.Insns.Count == 0) return res;
        _budget = 200_000;
        try { Exec(owner, m, null, concrete: false, depth: 0, collect: res); }
        catch (Exception ex) { Dbg(owner + "." + m.Name, ex); }
        return res.Where(Printable).Distinct().ToList();
    }

    /// <summary>Похоже на осмысленный текст: латиница/кириллица/цифры/пунктуация, есть буквы. Отсекает мусор неверного ключа.</summary>
    public static bool Plausible(string s)
    {
        if (!Printable(s)) return false;
        int ok = 0, letters = 0;
        foreach (char c in s)
        {
            if ((c >= 0x20 && c <= 0x7E) || (c >= 0x400 && c <= 0x4FF) || c is '—' or '–' or '«' or '»' or '…' or '§' or '°' or '•') ok++;
            if (char.IsLetter(c)) letters++;
        }
        if (ok < s.Length * 0.9 || letters < 2) return false;
        // промежуточные base64-заготовки («l4ZXlBhFVA==») — не результат
        if (s.Length <= 64 && s.EndsWith('=') && Base64Like.IsMatch(s)) return false;
        return true;
    }

    private static readonly System.Text.RegularExpressions.Regex Base64Like = new(@"^[A-Za-z0-9+/]+=*$", System.Text.RegularExpressions.RegexOptions.Compiled);

    public static bool Printable(string s)
    {
        if (s.Length < 3 || s.Length > 400) return false;
        int good = 0;
        foreach (char c in s) if (c >= 0x20 && c < 0xFFFE && !char.IsControl(c) && !char.IsSurrogate(c)) good++;
        return good >= s.Length * 0.95;
    }

    // ------------------------------------------------------------------ интерпретатор

    private (MethodInfo M, Dictionary<int, int> Index) Prepare(MethodInfo m)
    {
        string key = m.Name + m.Desc + "@" + m.GetHashCode();
        if (_prepared.TryGetValue(key, out var p)) return p;
        var idx = new Dictionary<int, int>(m.Insns.Count);
        for (int i = 0; i < m.Insns.Count; i++) idx[m.Insns[i].Pc] = i;
        p = (m, idx);
        _prepared[key] = p;
        return p;
    }

    private object? Exec(string owner, MethodInfo m, object?[]? args, bool concrete, int depth, List<string>? collect)
    {
        if (depth > 6) throw new AbortException("глубина");
        var (_, index) = Prepare(m);
        var code = m.Code!;
        var cf = CurrentClass;
        var locals = new Dictionary<int, object?>();
        if (args is not null)
        {
            int slot = m.IsStatic ? 0 : 1;
            foreach (var a in args) { locals[slot] = a; slot += a is long or double ? 2 : 1; }
        }
        var st = new List<object?>(16);
        int i = 0;
        var insns = m.Insns;

        object? Pop() { if (st.Count == 0) return Unknown.V; var v = st[^1]; st.RemoveAt(st.Count - 1); return v; }
        void Push(object? v) => st.Add(v);
        bool Known(object? v) => v is not Unknown && v is not NewObj { Value: null };
        object? Real(object? v) => v is NewObj { Value: not null } no ? no.Value : v;

        while (i < insns.Count)
        {
            if (--_budget < 0 || TimeUp) throw new AbortException("бюджет");
            var ins = insns[i];
            byte op = ins.Op;
            int next = i + 1;
            try
            {
                switch (op)
                {
                    case 0: break;
                    case 1: Push(null); break;
                    case >= 2 and <= 8: Push(op - 3); break;
                    case 9: Push(0L); break;
                    case 10: Push(1L); break;
                    case 11: Push(0f); break;
                    case 12: Push(1f); break;
                    case 13: Push(2f); break;
                    case 14: Push(0d); break;
                    case 15: Push(1d); break;
                    case 16: case 17: Push(ins.Operand); break;
                    case 18: case 19: case 20: Push(Ldc(cf, ins.Operand)); break;
                    case >= 21 and <= 25: Push(locals.GetValueOrDefault(ins.Operand, Unknown.V)); break;
                    case >= 26 and <= 45: Push(locals.GetValueOrDefault((op - 26) % 4, Unknown.V)); break;
                    case >= 46 and <= 53:
                    {
                        var idxv = Pop(); var arr = Real(Pop());
                        if (idxv is not int ix || !Known(arr) || arr is null) { Push(Unknown.V); break; }
                        Push(ArrGet(arr, ix, op));
                        break;
                    }
                    case >= 54 and <= 58: locals[ins.Operand] = Real(Pop()); break;
                    case >= 59 and <= 78: locals[(op - 59) % 4] = Real(Pop()); break;
                    case >= 79 and <= 86:
                    {
                        var val = Real(Pop()); var idxv = Pop(); var arr = Real(Pop());
                        if (idxv is int ix && arr is not null && Known(arr) && Known(val)) ArrSet(arr, ix, val, op);
                        else if (arr is not null && arr is not Unknown && !concrete) Poison(arr);
                        break;
                    }
                    case 87: Pop(); break;
                    case 88: { var v = Pop(); if (v is not (long or double)) Pop(); break; }
                    case 89: { var v = Pop(); Push(v); Push(v); break; }
                    case 90: { var a = Pop(); var b = Pop(); Push(a); Push(b); Push(a); break; }
                    case 91: { var a = Pop(); var b = Pop(); var c = Pop(); Push(a); Push(c); Push(b); Push(a); break; }
                    case 92:
                    {
                        var a = Pop();
                        if (a is long or double) { Push(a); Push(a); }
                        else { var b = Pop(); Push(b); Push(a); Push(b); Push(a); }
                        break;
                    }
                    case 93: { var a = Pop(); var b = Pop(); if (a is long or double) { Push(a); Push(b); Push(a); } else { var c = Pop(); Push(b); Push(a); Push(c); Push(b); Push(a); } break; }
                    case 95: { var a = Pop(); var b = Pop(); Push(a); Push(b); break; }
                    case >= 96 and <= 115: Arith(st, op); break;
                    case >= 116 and <= 119: { var v = Pop(); Push(v switch { int x => -x, long x => -x, float x => -x, double x => -x, _ => Unknown.V }); break; }
                    case >= 120 and <= 131: Bits(st, op); break;
                    case 132:
                    {
                        var v = locals.GetValueOrDefault(ins.Operand, Unknown.V);
                        locals[ins.Operand] = v is int x ? x + ins.Operand2 : Unknown.V;
                        break;
                    }
                    case >= 133 and <= 147: Push(Convert(Pop(), op)); break;
                    case >= 148 and <= 152:
                    {
                        var b = Pop(); var a = Pop();
                        if (a is long la && b is long lb) Push(la.CompareTo(lb));
                        else if (a is float fa && b is float fb) Push(float.IsNaN(fa) || float.IsNaN(fb) ? (op == 149 ? -1 : 1) : fa.CompareTo(fb));
                        else if (a is double da && b is double db) Push(double.IsNaN(da) || double.IsNaN(db) ? (op == 151 ? -1 : 1) : da.CompareTo(db));
                        else Push(Unknown.V);
                        break;
                    }
                    case >= 153 and <= 158:
                    {
                        var v = Pop();
                        if (!concrete) break;
                        int x = v is int iv ? iv : v is bool bv ? (bv ? 1 : 0) : v is char cv ? cv : throw new AbortException("ветвление");
                        bool jump = op switch { 153 => x == 0, 154 => x != 0, 155 => x < 0, 156 => x >= 0, 157 => x > 0, _ => x <= 0 };
                        if (jump) next = Target(index, ins.Operand);
                        break;
                    }
                    case >= 159 and <= 164:
                    {
                        var b = Pop(); var a = Pop();
                        if (!concrete) break;
                        int x = a is int ai ? ai : a is char ac ? ac : throw new AbortException("ветвление");
                        int y = b is int bi ? bi : b is char bc ? bc : throw new AbortException("ветвление");
                        bool jump = op switch { 159 => x == y, 160 => x != y, 161 => x < y, 162 => x >= y, 163 => x > y, _ => x <= y };
                        if (jump) next = Target(index, ins.Operand);
                        break;
                    }
                    case 165: case 166:
                    {
                        var b = Pop(); var a = Pop();
                        if (!concrete) break;
                        if (!Known(a) || !Known(b)) throw new AbortException("ветвление");
                        bool same = ReferenceEquals(Real(a), Real(b));
                        if (op == 165 ? same : !same) next = Target(index, ins.Operand);
                        break;
                    }
                    case 198: case 199:
                    {
                        var v = Pop();
                        if (!concrete) break;
                        if (v is Unknown) throw new AbortException("ветвление");
                        bool isNull = Real(v) is null;
                        if (op == 198 ? isNull : !isNull) next = Target(index, ins.Operand);
                        break;
                    }
                    case 167: case 200:
                        if (concrete) next = Target(index, ins.Operand);
                        else { st.Clear(); }
                        break;
                    case 170: case 171:
                    {
                        var v = Pop();
                        if (!concrete) { st.Clear(); break; }
                        if (v is not int key) throw new AbortException("switch");
                        next = Target(index, SwitchTarget(code, ins, key));
                        break;
                    }
                    case >= 172 and <= 176:
                    {
                        var v = Real(Pop());
                        if (concrete) return v;
                        st.Clear();
                        break;
                    }
                    case 177:
                        if (concrete) return null;
                        st.Clear();
                        break;
                    case 178:
                    {
                        var r = cf.Member(ins.Operand);
                        if (r is null) { Push(Unknown.V); break; }
                        Push(GetStatic(r));
                        break;
                    }
                    case 179:
                    {
                        var r = cf.Member(ins.Operand);
                        var v = Real(Pop());
                        if (r is not null && _isOwn(r.Owner)) _statics[r.Owner + "." + r.Name] = v;
                        break;
                    }
                    case 180: { Pop(); Push(Unknown.V); break; }
                    case 181: { Pop(); Pop(); break; }
                    case 182: case 183: case 184: case 185:
                    {
                        var r = cf.Member(ins.Operand);
                        if (r is null) throw new AbortException("ссылка");
                        int argc = ArgCount(r.Desc);
                        var a = new object?[argc];
                        for (int k = argc - 1; k >= 0; k--) a[k] = Real(Pop());
                        object? recv = op == 184 ? null : Pop();
                        var result = Invoke(r, op, recv, a, depth, concrete, st, locals);
                        string ret = r.Desc[(r.Desc.IndexOf(')') + 1)..];
                        if (ret != "V")
                        {
                            Push(result);
                            if (collect is not null && result is string rs && (op == 184 || r.Name == "toString") && !IsLdcString(cf, rs)) collect.Add(rs);
                        }
                        else if (r.Name == "<init>" && collect is not null && recv is NewObj { Value: string ns } && !IsLdcString(cf, ns)) collect.Add(ns);
                        break;
                    }
                    case 186:
                    {
                        // invokedynamic: makeConcatWithConstants и лямбды — результат неизвестен
                        int nt = cf.TagAt(ins.Operand) == CpTag.InvokeDynamic ? cf.Cp[ins.Operand].B : 0;
                        string desc = nt > 0 ? cf.Utf8(cf.Cp[nt].B) : "()V";
                        int argc = ArgCount(desc);
                        for (int k = 0; k < argc; k++) Pop();
                        if (!desc.EndsWith(")V")) Push(Unknown.V);
                        break;
                    }
                    case 187: Push(new NewObj { Cls = cf.ClassName(ins.Operand) }); break;
                    case 188:
                    {
                        var n = Pop();
                        if (n is not int len || len < 0 || len > 1 << 20) { Push(Unknown.V); break; }
                        Push(ins.Operand switch
                        {
                            4 => new bool[len], 5 => new char[len], 6 => new float[len], 7 => new double[len],
                            8 => new sbyte[len], 9 => new short[len], 10 => new int[len], 11 => new long[len], _ => (object)Unknown.V,
                        });
                        break;
                    }
                    case 189:
                    {
                        var n = Pop();
                        Push(n is int len && len >= 0 && len <= 1 << 20 ? new object?[len] : Unknown.V);
                        break;
                    }
                    case 190: { var a = Real(Pop()); Push(a is Array arr ? arr.Length : Unknown.V); break; }
                    case 191:
                        if (concrete) throw new AbortException("throw");
                        st.Clear();
                        break;
                    case 192: break;
                    case 193: { Pop(); Push(Unknown.V); break; }
                    case 194: case 195: Pop(); break;
                    case 196:
                    {
                        int w = ins.Operand;
                        int idx = BinaryPrimitives.ReadUInt16BigEndian(code.AsSpan(ins.Pc + 2));
                        if (w == 132) { short c = BinaryPrimitives.ReadInt16BigEndian(code.AsSpan(ins.Pc + 4)); var v = locals.GetValueOrDefault(idx, Unknown.V); locals[idx] = v is int x ? x + c : Unknown.V; }
                        else if (w is >= 21 and <= 25) Push(locals.GetValueOrDefault(idx, Unknown.V));
                        else if (w is >= 54 and <= 58) locals[idx] = Real(Pop());
                        else throw new AbortException("wide");
                        break;
                    }
                    case 197:
                    {
                        int dims = ins.Len >= 4 ? code[ins.Pc + 3] : 1;
                        for (int k = 0; k < dims; k++) Pop();
                        Push(Unknown.V);
                        break;
                    }
                    default:
                        if (concrete) throw new AbortException("op " + op);
                        st.Clear();
                        break;
                }
            }
            catch (AbortException) when (!concrete) { st.Clear(); }
            catch (Exception ex) when (ex is not AbortException)
            {
                if (concrete) throw new AbortException(ex.Message);
                st.Clear();
            }
            i = next;
        }
        return Unknown.V;
    }

    [ThreadStatic] private static ClassFile? _current;
    private ClassFile CurrentClass => _current ?? throw new AbortException("класс");
    public void Enter(ClassFile cf) => _current = cf;

    private static int Target(Dictionary<int, int> index, int pc) => index.TryGetValue(pc, out var i) ? i : throw new AbortException("переход");

    private static int SwitchTarget(byte[] code, Insn ins, int key)
    {
        int p = (ins.Pc + 4) & ~3;
        int def = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p));
        if (ins.Op == 170)
        {
            int lo = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 4));
            int hi = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 8));
            if (key < lo || key > hi) return ins.Pc + def;
            return ins.Pc + BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 12 + (key - lo) * 4));
        }
        int n = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 4));
        for (int k = 0; k < n; k++)
        {
            int match = BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 8 + k * 8));
            if (match == key) return ins.Pc + BinaryPrimitives.ReadInt32BigEndian(code.AsSpan(p + 12 + k * 8));
        }
        return ins.Pc + def;
    }

    private static object? Ldc(ClassFile cf, int i) => cf.TagAt(i) switch
    {
        CpTag.Integer => (int)cf.Cp[i].Raw,
        CpTag.Float => BitConverter.Int32BitsToSingle((int)cf.Cp[i].Raw),
        CpTag.Long => cf.Cp[i].Raw,
        CpTag.Double => BitConverter.Int64BitsToDouble(cf.Cp[i].Raw),
        CpTag.String => cf.LdcString(i),
        _ => Unknown.V,
    };

    private static bool IsLdcString(ClassFile cf, string s) => cf.Strings.Contains(s);

    private static void Poison(object arr) { /* массив частично известен — оставляем как есть, значения по умолчанию */ }

    private static object? ArrGet(object arr, int ix, byte op)
    {
        return arr switch
        {
            int[] a => a[ix], long[] a => a[ix], float[] a => a[ix], double[] a => a[ix],
            char[] a => (int)a[ix], sbyte[] a => (int)a[ix], bool[] a => a[ix] ? 1 : 0, short[] a => (int)a[ix],
            object?[] a => a[ix], _ => Unknown.V,
        };
    }

    private static void ArrSet(object arr, int ix, object? v, byte op)
    {
        switch (arr)
        {
            case int[] a: a[ix] = ToInt(v); break;
            case long[] a: a[ix] = v is long l ? l : ToInt(v); break;
            case float[] a: a[ix] = v is float f ? f : ToInt(v); break;
            case double[] a: a[ix] = v is double d ? d : ToInt(v); break;
            case char[] a: a[ix] = (char)ToInt(v); break;
            case sbyte[] a: a[ix] = (sbyte)ToInt(v); break;
            case bool[] a: a[ix] = ToInt(v) != 0; break;
            case short[] a: a[ix] = (short)ToInt(v); break;
            case object?[] a: a[ix] = v; break;
        }
    }

    private static int ToInt(object? v) => v switch { int i => i, char c => c, bool b => b ? 1 : 0, _ => throw new AbortException("тип") };

    private static void Arith(List<object?> st, byte op)
    {
        var b = st.Count > 0 ? st[^1] : Unknown.V; if (st.Count > 0) st.RemoveAt(st.Count - 1);
        var a = st.Count > 0 ? st[^1] : Unknown.V; if (st.Count > 0) st.RemoveAt(st.Count - 1);
        int kind = (op - 96) % 4, what = (op - 96) / 4;   // 0 add, 1 sub, 2 mul, 3 div, 4 rem
        object? r = Unknown.V;
        if (kind == 0 && a is int x && b is int y)
            r = what switch { 0 => x + y, 1 => x - y, 2 => x * y, 3 => y == 0 ? throw new AbortException("/0") : (x == int.MinValue && y == -1 ? x : x / y), _ => y == 0 ? throw new AbortException("/0") : (y == -1 ? 0 : x % y) };
        else if (kind == 1 && a is long lx && b is long ly)
            r = what switch { 0 => lx + ly, 1 => lx - ly, 2 => lx * ly, 3 => ly == 0 ? throw new AbortException("/0") : (ly == -1 ? -lx : lx / ly), _ => ly == 0 ? throw new AbortException("/0") : (ly == -1 ? 0 : lx % ly) };
        else if (kind == 2 && a is float fx && b is float fy)
            r = what switch { 0 => fx + fy, 1 => fx - fy, 2 => fx * fy, 3 => fx / fy, _ => fx % fy };
        else if (kind == 3 && a is double dx && b is double dy)
            r = what switch { 0 => dx + dy, 1 => dx - dy, 2 => dx * dy, 3 => dx / dy, _ => dx % dy };
        st.Add(r);
    }

    private static void Bits(List<object?> st, byte op)
    {
        var b = st.Count > 0 ? st[^1] : Unknown.V; if (st.Count > 0) st.RemoveAt(st.Count - 1);
        var a = st.Count > 0 ? st[^1] : Unknown.V; if (st.Count > 0) st.RemoveAt(st.Count - 1);
        object? r = Unknown.V;
        switch (op)
        {
            case 120 when a is int x && b is int s: r = x << (s & 31); break;
            case 121 when a is long x && b is int s: r = x << (s & 63); break;
            case 122 when a is int x && b is int s: r = x >> (s & 31); break;
            case 123 when a is long x && b is int s: r = x >> (s & 63); break;
            case 124 when a is int x && b is int s: r = (int)((uint)x >> (s & 31)); break;
            case 125 when a is long x && b is int s: r = (long)((ulong)x >> (s & 63)); break;
            case 126 when a is int x && b is int y: r = x & y; break;
            case 127 when a is long x && b is long y: r = x & y; break;
            case 128 when a is int x && b is int y: r = x | y; break;
            case 129 when a is long x && b is long y: r = x | y; break;
            case 130 when a is int x && b is int y: r = x ^ y; break;
            case 131 when a is long x && b is long y: r = x ^ y; break;
        }
        st.Add(r);
    }

    private static object? Convert(object? v, byte op)
    {
        if (v is char c) v = (int)c;
        return op switch
        {
            133 when v is int i => (long)i, 134 when v is int i => (float)i, 135 when v is int i => (double)i,
            136 when v is long l => (int)l, 137 when v is long l => (float)l, 138 when v is long l => (double)l,
            139 when v is float f => F2I(f), 140 when v is float f => (long)f, 141 when v is float f => (double)f,
            142 when v is double d => D2I(d), 143 when v is double d => (long)d, 144 when v is double d => (float)d,
            145 when v is int i => (int)(sbyte)i, 146 when v is int i => (int)(char)i, 147 when v is int i => (int)(short)i,
            _ => Unknown.V,
        };
    }

    private static int F2I(float f) => float.IsNaN(f) ? 0 : f >= int.MaxValue ? int.MaxValue : f <= int.MinValue ? int.MinValue : (int)f;
    private static int D2I(double d) => double.IsNaN(d) ? 0 : d >= int.MaxValue ? int.MaxValue : d <= int.MinValue ? int.MinValue : (int)d;

    private object? GetStatic(MemberRef r)
    {
        if (_statics.TryGetValue(r.Owner + "." + r.Name, out var v)) return v;
        if (r.Owner == "java/nio/charset/StandardCharsets") return new Marker { Kind = "charset:" + r.Name };
        return Unknown.V;
    }

    private static int ArgCount(string desc)
    {
        int n = 0, i = 1;
        while (i < desc.Length && desc[i] != ')')
        {
            while (desc[i] == '[') i++;
            if (desc[i] == 'L') i = desc.IndexOf(';', i);
            i++; n++;
        }
        return n;
    }

    // ------------------------------------------------------------------ вызовы

    private object? Invoke(MemberRef r, byte op, object? recv, object?[] a, int depth, bool concrete, List<object?> st, Dictionary<int, object?> locals)
    {
        bool allKnown = a.All(x => x is not Unknown && x is not NewObj { Value: null }) && (recv is null || recv is not Unknown);

        // собственный статический метод мода
        if (op == 184 && _isOwn(r.Owner))
        {
            if (!allKnown) return Unknown.V;
            var target = _findStatic(r.Owner, r.Name, r.Desc);
            if (target?.Code is null) return Unknown.V;
            var saved = _current;
            try
            {
                var ownerCf = FindClass?.Invoke(r.Owner);
                if (ownerCf is not null) _current = ownerCf;
                return Exec(r.Owner, target, a, concrete: true, depth + 1, collect: null);
            }
            catch (AbortException ex) { Dbg("call " + r.Owner + "." + r.Name, ex); return Unknown.V; }
            finally { _current = saved; }
        }
        if (!allKnown)
        {
            if (r.Name == "<init>" && recv is NewObj no0) no0.Value = null;
            return Unknown.V;
        }
        object? self = recv is NewObj { Value: not null } nv ? nv.Value : recv;

        switch (r.Owner)
        {
            case "java/lang/String":
                if (r.Name == "<init>" && recv is NewObj ns)
                {
                    string? s = r.Desc switch
                    {
                        "([C)V" => new string((char[])a[0]!),
                        "([CII)V" => new string((char[])a[0]!, (int)a[1]!, (int)a[2]!),
                        "([B)V" or "([BLjava/nio/charset/Charset;)V" or "([BLjava/lang/String;)V" => Encoding.UTF8.GetString(ToBytes(a[0])),
                        "([BII)V" => Encoding.UTF8.GetString(ToBytes(a[0]), (int)a[1]!, (int)a[2]!),
                        "(Ljava/lang/String;)V" => (string)a[0]!,
                        "()V" => "",
                        _ => null,
                    };
                    if (s is null) return Unknown.V;
                    ns.Value = s;
                    Replace(st, locals, ns, s);
                    return null;
                }
                if (self is string str)
                    return r.Name switch
                    {
                        "toCharArray" => str.ToCharArray(),
                        "charAt" => (int)str[(int)a[0]!],
                        "length" => str.Length,
                        "intern" or "toString" or "trim" or "strip" => r.Name is "trim" or "strip" ? str.Trim() : str,
                        "getBytes" => ToSBytes(Encoding.UTF8.GetBytes(str)),
                        "concat" => str + (string)a[0]!,
                        "substring" => a.Length == 1 ? str[(int)a[0]!..] : str[(int)a[0]!..(int)a[1]!],
                        "hashCode" => JavaHash(str),
                        "isEmpty" => str.Length == 0 ? 1 : 0,
                        "replace" when r.Desc == "(CC)Ljava/lang/String;" => str.Replace((char)(int)a[0]!, (char)(int)a[1]!),
                        "toLowerCase" => str.ToLowerInvariant(),
                        "toUpperCase" => str.ToUpperInvariant(),
                        "indexOf" when r.Desc == "(I)I" => str.IndexOf((char)(int)a[0]!),
                        _ => Unknown.V,
                    };
                if (op == 184 && r.Name == "valueOf")
                    return r.Desc switch
                    {
                        "([C)Ljava/lang/String;" => new string((char[])a[0]!),
                        "(C)Ljava/lang/String;" => ((char)(int)a[0]!).ToString(),
                        "(I)Ljava/lang/String;" => ((int)a[0]!).ToString(),
                        "(Ljava/lang/Object;)Ljava/lang/String;" => a[0] as string ?? (object)Unknown.V,
                        _ => Unknown.V,
                    };
                if (op == 184 && r.Name == "copyValueOf" && a[0] is char[] cv) return new string(cv);
                return Unknown.V;

            case "java/lang/StringBuilder" or "java/lang/StringBuffer":
                if (r.Name == "<init>" && recv is NewObj nb)
                {
                    var sb = new StringBuilder(r.Desc == "(Ljava/lang/String;)V" ? (string)a[0]! : "");
                    nb.Value = sb;
                    Replace(st, locals, nb, sb);
                    return null;
                }
                if (self is StringBuilder b)
                {
                    switch (r.Name)
                    {
                        case "append":
                            switch (r.Desc[1])
                            {
                                case 'C': b.Append((char)(int)a[0]!); break;
                                case 'I': b.Append((int)a[0]!); break;
                                case 'J': b.Append((long)a[0]!); break;
                                case '[': b.Append((char[])a[0]!); break;
                                default: if (a[0] is string s2) b.Append(s2); else if (a[0] is StringBuilder s3) b.Append(s3); else return Unknown.V; break;
                            }
                            return b;
                        case "toString": return b.ToString();
                        case "length": return b.Length;
                        case "charAt": return (int)b[(int)a[0]!];
                        case "setCharAt": b[(int)a[0]!] = (char)(int)a[1]!; return null;
                        case "reverse": { var arr = b.ToString().ToCharArray(); Array.Reverse(arr); b.Clear().Append(arr); return b; }
                        case "insert" when r.Desc.StartsWith("(IC)"): b.Insert((int)a[0]!, (char)(int)a[1]!); return b;
                        case "deleteCharAt": b.Remove((int)a[0]!, 1); return b;
                        case "setLength": b.Length = (int)a[0]!; return null;
                    }
                }
                return Unknown.V;

            case "java/util/Base64":
                if (r.Name is "getDecoder" or "getMimeDecoder" or "getUrlDecoder") return new Marker { Kind = "b64:" + r.Name };
                return Unknown.V;
            case "java/util/Base64$Decoder":
                if (r.Name == "decode" && self is Marker mk)
                {
                    string s = a[0] is string ds ? ds : a[0] is sbyte[] db ? Encoding.ASCII.GetString(ToBytes(db)) : "";
                    if (mk.Kind.EndsWith("getUrlDecoder")) s = s.Replace('-', '+').Replace('_', '/');
                    s = s.Trim();
                    while (s.Length % 4 != 0) s += "=";
                    return ToSBytes(System.Convert.FromBase64String(s));
                }
                return Unknown.V;
            case "java/nio/charset/Charset" when r.Name == "forName":
                return new Marker { Kind = "charset" };
            case "java/lang/Integer":
                return r.Name switch
                {
                    "valueOf" or "intValue" => a.Length > 0 ? a[0] : self,
                    "parseInt" when a[0] is string ps && int.TryParse(ps, out var pi) => pi,
                    _ => Unknown.V,
                };
            case "java/lang/Character":
                return r.Name switch { "valueOf" or "charValue" => a.Length > 0 ? a[0] : self, _ => Unknown.V };
            case "java/lang/Math":
                return r.Name switch
                {
                    "abs" when a[0] is int ai => Math.Abs(ai),
                    "max" when a[0] is int m1 && a[1] is int m2 => Math.Max(m1, m2),
                    "min" when a[0] is int n1 && a[1] is int n2 => Math.Min(n1, n2),
                    _ => Unknown.V,
                };
            case "java/lang/System" when r.Name == "arraycopy":
            {
                if (a[0] is Array src && a[2] is Array dst && a[1] is int sp && a[3] is int dp && a[4] is int len)
                    Array.Copy(src, sp, dst, dp, len);
                return null;
            }
            case "java/util/Arrays" when r.Name == "copyOf" && a[1] is int nl:
            {
                if (a[0] is char[] ca) { var n = new char[nl]; Array.Copy(ca, n, Math.Min(nl, ca.Length)); return n; }
                if (a[0] is sbyte[] ba) { var n = new sbyte[nl]; Array.Copy(ba, n, Math.Min(nl, ba.Length)); return n; }
                if (a[0] is int[] ia) { var n = new int[nl]; Array.Copy(ia, n, Math.Min(nl, ia.Length)); return n; }
                return Unknown.V;
            }
            case "java/lang/Object" when r.Name == "<init>":
                return null;
        }
        if (self is char[] carr && r.Name == "clone") return (char[])carr.Clone();
        if (self is int[] iarr && r.Name == "clone") return (int[])iarr.Clone();
        if (self is sbyte[] barr && r.Name == "clone") return (sbyte[])barr.Clone();
        return Unknown.V;
    }

    public Func<string, ClassFile?>? FindClass;

    private static void Replace(List<object?> st, Dictionary<int, object?> locals, NewObj marker, object value)
    {
        for (int k = 0; k < st.Count; k++) if (ReferenceEquals(st[k], marker)) st[k] = value;
        foreach (var key in locals.Keys.ToList()) if (ReferenceEquals(locals[key], marker)) locals[key] = value;
    }

    private static byte[] ToBytes(object? v) => v switch
    {
        sbyte[] s => s.Select(x => (byte)x).ToArray(),
        _ => throw new AbortException("bytes"),
    };

    private static sbyte[] ToSBytes(byte[] b) => b.Select(x => (sbyte)x).ToArray();

    private static int JavaHash(string s) { int h = 0; foreach (char c in s) h = 31 * h + c; return h; }
}
