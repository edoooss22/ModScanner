using System.Text.RegularExpressions;
using ModScanner.Core;

namespace ModScanner.Analysis;

/// <summary>Класс мода в модели: методы, факты уровня класса, Mixin-сведения.</summary>
internal sealed class ClassNode
{
    public ClassEntry Entry = null!;
    public ClassFile Cf => Entry.Cf;
    public string Name => Cf.Name;
    public string Outer = "";                         // внешний класс (до первого $) — «логическая единица»
    public bool IsLibrary;                             // сторонняя библиотека (kotlin, netty, okhttp…)
    public bool IsMixin;
    public List<string> MixinTargets = new();          // классы-цели (как в аннотации: class_310 или net/minecraft/client/Minecraft)
    public List<MethodNode> Methods = new();
    public Dictionary<string, MethodNode> BySig = new(StringComparer.Ordinal);
    public List<string> PacketCollections = new();     // поля-коллекции пакетов: «имя: сигнатура»
    public HashSet<string> HeldPacketTypes = new(StringComparer.Ordinal);   // простые имена пакетов в этих коллекциях
    public bool IsNettyHandler;
    public bool ExtendsClassLoader;
    public List<Hook> Hooks = new();
    public string SimpleName => Cf.SimpleName;
}

/// <summary>Метод мода: прямые обращения (атомы) и транзитивные — с учётом вызываемых методов мода.</summary>
internal sealed class MethodNode
{
    public ClassNode Owner = null!;
    public MethodInfo Mi = null!;
    public AtomSet Direct;
    public AtomSet Closure;
    public readonly Dictionary<int, List<string>> Hits = new();
    public readonly List<MethodNode> Callees = new();
    public readonly List<string> Strings = new();
    public readonly List<double> Doubles = new();
    public readonly List<string> Decrypted = new();      // строки, восстановленные эмуляцией расшифровщика
    public Hook? AsHook;
    public string Name => Mi.Name;

    public void Hit(int atom, string pretty)
    {
        Direct.Add(atom);
        if (!Hits.TryGetValue(atom, out var l)) Hits[atom] = l = new List<string>();
        if (l.Count < 8 && !l.Contains(pretty)) l.Add(pretty);
    }
}

/// <summary>Инъекция Mixin: в какой метод игры, каким способом, в какую точку.</summary>
internal sealed class Hook
{
    public ClassNode Mixin = null!;
    public MethodNode Handler = null!;
    public string Kind = "";                            // Inject, Redirect, ModifyReturnValue, ModifyConstant…
    public List<string> Selectors = new();
    public HashSet<string> TargetKeys = new(StringComparer.Ordinal);
    public List<string> TargetPretty = new();
    public string AtValue = "";
    public HashSet<string> AtKeys = new(StringComparer.Ordinal);
    public List<string> AtPretty = new();
    public bool Cancellable;
    public List<double> Constants = new();

    public bool Targets(params string[] keys) => keys.Any(TargetKeys.Contains);
    public bool At(params string[] keys) => keys.Any(AtKeys.Contains);

    /// <summary>Инъекция меняет значение: результат, аргумент, константу или сам вызов.</summary>
    public bool ChangesValue =>
        Kind is "Redirect" or "ModifyArg" or "ModifyArgs" or "ModifyVariable" or "ModifyConstant" or "ModifyReturnValue"
            or "ModifyExpressionValue" or "WrapOperation" or "Overwrite" or "ModifyReceiver"
        || (Kind == "Inject" && Handler.Closure.Has(Vocab.SetReturn));

    public string Describe()
    {
        string t = TargetPretty.Count > 0 ? string.Join(", ", TargetPretty.Take(3)) : string.Join(", ", Selectors.Take(3));
        string at = AtValue.Length > 0 ? $" @At({AtValue}{(AtPretty.Count > 0 ? " " + AtPretty[0] : "")})" : "";
        string c = Constants.Count > 0 ? $" константа {string.Join(", ", Constants.Select(x => x.ToString(System.Globalization.CultureInfo.InvariantCulture)))}" : "";
        return $"@{Kind} → {t}{at}{c}{(Cancellable ? " cancellable" : "")}  [{Mixin.SimpleName}.{Handler.Name}]";
    }
}

/// <summary>
/// Модель одного jar: классы, граф вызовов, атомы. Строится один раз и используется всеми анализаторами.
/// </summary>
internal sealed class ModModel
{
    public ModUnit Unit = null!;
    public GameNames Names = null!;
    public readonly Dictionary<string, ClassNode> Classes = new(StringComparer.Ordinal);
    public readonly Dictionary<string, List<ClassNode>> Units = new(StringComparer.Ordinal);
    public readonly List<Hook> Hooks = new();
    public readonly List<string> Log = new();
    public bool IsLibraryJar;

    private readonly Dictionary<string, (string[] Keys, string Pretty)> _accessors = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Refmap> _refmapByMixin = new(StringComparer.Ordinal);

    public const int ClosureDepth = 4;
    public const int HubLimit = 40;

    private static readonly string[] LibraryPrefixes =
    {
        "kotlin/", "kotlinx/", "org/", "com/google/", "io/netty/", "it/unimi/", "com/fasterxml/", "okhttp3/", "okio/", "javax/",
        "com/mojang/", "com/llamalad7/", "imgui/", "com/neovisionaries/", "baritone/", "oshi/",
        "com/sun/", "net/java/", "io/github/classgraph/", "com/formdev/", "club/minnced/", "com/jagrosh/", "de/jcm/", "com/typesafe/",
        "dev/isxander/", "me/shedaniel/", "com/terraformersmc/", "io/wispforest/", "com/github/benmanes/", "reactor/", "io/reactivex/",
        "com/squareup/", "gnu/", "lombok/", "jdk/", "sun/", "META-INF/", "com/ibm/", "net/jodah/", "com/viaversion/", "com/github/luben/",
        "su/plo/", "me/lucko/", "dev/lambdaurora/", "net/kyori/", "com/electronwill/", "org/luaj/", "xyz/nucleoid/",
        "javassist/", "net/bytebuddy/", "com/esotericsoftware/", "jnr/", "com/headius/", "de/javakaffee/", "org/objectweb/", "io/github/spair/", "meteordevelopment/orbit/", "meteordevelopment/starscript/",
    };

    private static readonly string[] LibraryMarkers = { "/lib/", "/libs/", "/shadow/", "/shaded/", "/repack/", "/repackaged/", "/relocated/", "/vendor/", "/thirdparty/", "/third_party/", "/deps/", "/dependencies/", "/embedded/" };

    public static bool IsLibraryPackage(string internalName)
    {
        foreach (var p in LibraryPrefixes) if (internalName.StartsWith(p, StringComparison.Ordinal)) return true;
        foreach (var mk in LibraryMarkers) if (internalName.Contains(mk, StringComparison.Ordinal)) return true;
        return internalName.StartsWith("io/sentry/", StringComparison.Ordinal);
    }

    public IEnumerable<ClassNode> OwnClasses => Classes.Values.Where(c => !c.IsLibrary);
    public IEnumerable<MethodNode> AllMethods => Classes.Values.SelectMany(c => c.Methods);

    public static ModModel Build(ModUnit u, GameNames names)
    {
        var m = new ModModel { Unit = u, Names = names };
        m.IsLibraryJar = u.IsLibrary;
        foreach (var e in u.Classes)
        {
            if (e.Cf.ParseError || e.MultiRelease || m.Classes.ContainsKey(e.Cf.Name)) continue;
            var c = new ClassNode { Entry = e };
            int d = e.Cf.Name.IndexOf('$');
            c.Outer = d > 0 ? e.Cf.Name[..d] : e.Cf.Name;
            c.IsLibrary = IsLibraryPackage(e.Cf.Name);
            foreach (var mi in e.Cf.Methods)
            {
                var mn = new MethodNode { Owner = c, Mi = mi };
                c.Methods.Add(mn);
                c.BySig[mi.Name + mi.Desc] = mn;
            }
            m.Classes[c.Name] = c;
            if (!m.Units.TryGetValue(c.Outer, out var l)) m.Units[c.Outer] = l = new List<ClassNode>();
            l.Add(c);
        }

        foreach (var mc in u.MixinConfigs)
            if (mc.Refmap is not null && u.Refmaps.TryGetValue(mc.Refmap, out var rm))
                foreach (var cls in mc.AllMixinClasses) m._refmapByMixin[cls] = rm;

        foreach (var c in m.Classes.Values) m.DetectMixin(c);
        foreach (var c in m.Classes.Values.Where(x => x.IsMixin)) m.CollectAccessors(c);
        m.DecryptStrings();
        foreach (var c in m.Classes.Values) { m.ClassFacts(c); foreach (var mn in c.Methods) m.ScanMethod(mn); }
        foreach (var c in m.Classes.Values.Where(x => x.IsMixin)) m.CollectHooks(c);
        foreach (var mn in m.AllMethods) m.ComputeClosure(mn);
        return m;
    }

    // ------------------------------------------------------------------ Mixin

    private const string MixinAnn = "org/spongepowered/asm/mixin/Mixin";

    private void DetectMixin(ClassNode c)
    {
        foreach (var a in c.Cf.Annotations)
        {
            if (a.TypeName != MixinAnn) continue;
            c.IsMixin = true;
            foreach (var t in a.Get("value")?.Classes() ?? Enumerable.Empty<string>()) c.MixinTargets.Add(t);
            foreach (var t in a.Get("targets")?.Strings() ?? Enumerable.Empty<string>()) c.MixinTargets.Add(t.Replace('.', '/'));
        }
    }

    private Refmap? RefmapFor(ClassNode c)
    {
        if (_refmapByMixin.TryGetValue(c.Name, out var r)) return r;
        foreach (var rm in Unit.Refmaps.Values) if (rm.ByClass.ContainsKey(c.Name)) return rm;
        return null;
    }

    private string MapSelector(ClassNode mixin, string sel)
    {
        var rm = RefmapFor(mixin);
        return rm?.Map(mixin.Name, sel) ?? sel;
    }

    /// <summary>Классы игры, от имени которых идёт обращение к члену: сам класс игры, цели mixin, игровой предок своего класса.</summary>
    public List<string> GameOwners(string owner)
    {
        var res = new List<string>();
        if (GameNames.IsGame(owner)) { res.Add(owner); return res; }
        string? c = owner;
        int guard = 0;
        while (c is not null && guard++ < 16)
        {
            if (GameNames.IsGame(c)) { res.Add(c); break; }
            if (!Classes.TryGetValue(c, out var cn)) break;
            if (cn.IsMixin)
            {
                foreach (var t in cn.MixinTargets)
                    if (GameNames.IsGame(t)) res.Add(t);
                    else res.AddRange(GameOwners(t));
                break;
            }
            c = cn.Cf.Super;
        }
        return res;
    }

    private static readonly Regex SelectorRx = new(@"^(?:L(?<owner>[^;]+);)?(?<name>[^(:]+)(?<desc>[(:].*)?$", RegexOptions.Compiled);

    /// <summary>Ключи членов для строки-селектора Mixin («method_5829», «Lnet/minecraft/class_1297;method_5829()…», «getBoundingBox»).</summary>
    private (HashSet<string> Keys, List<string> Pretty) ResolveSelector(ClassNode mixin, string sel, IEnumerable<string> defaultOwners)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var pretty = new List<string>();
        var mt = SelectorRx.Match(sel.Trim());
        if (!mt.Success) return (keys, pretty);
        string name = mt.Groups["name"].Value.Trim();
        string owner = mt.Groups["owner"].Success ? mt.Groups["owner"].Value : "";
        var owners = owner.Length > 0 ? new List<string> { owner } : defaultOwners.ToList();
        foreach (var o in owners)
        {
            var gos = GameOwners(o);
            if (gos.Count == 0 && GameNames.IsGame(o)) gos.Add(o);
            foreach (var go in gos)
            {
                string n = name;
                if (!GameNames.IsIntermediaryMember(n) && Names.Canon(go) != go && n != "<init>")
                {
                    // мод под intermediary, но селектор в читаемых именах (нет refmap) — пробуем перевести
                    var inter = Names.YarnToIntermediary(Names.Canon(go), n);
                    if (inter is not null) n = inter;
                }
                foreach (var k in Names.MemberKeys(go, n)) keys.Add(k);
                pretty.Add(Names.Pretty(go, n));
            }
        }
        return (keys, pretty.Distinct().ToList());
    }

    private void CollectAccessors(ClassNode c)
    {
        foreach (var mn in c.Methods)
            foreach (var a in mn.Mi.Annotations)
            {
                bool acc = a.TypeName == "org/spongepowered/asm/mixin/gen/Accessor";
                bool inv = a.TypeName == "org/spongepowered/asm/mixin/gen/Invoker";
                if (!acc && !inv) continue;
                string target = a.Get("value")?.Str ?? "";
                if (target.Length == 0) target = DeriveAccessorName(mn.Name, inv);
                string mapped = MapSelector(c, target);
                var (keys, pretty) = ResolveSelector(c, mapped, c.MixinTargets);
                bool setter = acc && mn.Mi.Desc.EndsWith(")V") && !mn.Mi.Desc.StartsWith("()");
                if (setter) foreach (var k in keys.ToList()) keys.Add(k + "=");
                _accessors[c.Name + "." + mn.Name + mn.Mi.Desc] = (keys.ToArray(), (pretty.FirstOrDefault() ?? target) + (setter ? " = …" : "") + $"  [через {(inv ? "@Invoker" : "@Accessor")} {c.SimpleName}.{mn.Name}]");
            }
    }

    private static string DeriveAccessorName(string method, bool invoker)
    {
        foreach (var p in invoker ? new[] { "invoke", "call" } : new[] { "get", "set", "is" })
            if (method.StartsWith(p) && method.Length > p.Length && char.IsUpper(method[p.Length]))
                return char.ToLowerInvariant(method[p.Length]) + method[(p.Length + 1)..];
        return method;
    }

    private static readonly Dictionary<string, string> InjectorKinds = new(StringComparer.Ordinal)
    {
        ["org/spongepowered/asm/mixin/injection/Inject"] = "Inject",
        ["org/spongepowered/asm/mixin/injection/Redirect"] = "Redirect",
        ["org/spongepowered/asm/mixin/injection/ModifyArg"] = "ModifyArg",
        ["org/spongepowered/asm/mixin/injection/ModifyArgs"] = "ModifyArgs",
        ["org/spongepowered/asm/mixin/injection/ModifyVariable"] = "ModifyVariable",
        ["org/spongepowered/asm/mixin/injection/ModifyConstant"] = "ModifyConstant",
        ["com/llamalad7/mixinextras/injector/ModifyReturnValue"] = "ModifyReturnValue",
        ["com/llamalad7/mixinextras/injector/ModifyExpressionValue"] = "ModifyExpressionValue",
        ["com/llamalad7/mixinextras/injector/ModifyReceiver"] = "ModifyReceiver",
        ["com/llamalad7/mixinextras/injector/WrapWithCondition"] = "WrapWithCondition",
        ["com/llamalad7/mixinextras/injector/v2/WrapWithCondition"] = "WrapWithCondition",
        ["com/llamalad7/mixinextras/injector/wrapoperation/WrapOperation"] = "WrapOperation",
        ["com/llamalad7/mixinextras/injector/wrapmethod/WrapMethod"] = "WrapMethod",
    };

    private void CollectHooks(ClassNode c)
    {
        foreach (var mn in c.Methods)
            foreach (var a in mn.Mi.Annotations)
            {
                string kind;
                if (a.TypeName == "org/spongepowered/asm/mixin/Overwrite") kind = "Overwrite";
                else if (!InjectorKinds.TryGetValue(a.TypeName, out kind!)) continue;

                var h = new Hook { Mixin = c, Handler = mn, Kind = kind };
                var selectors = kind == "Overwrite" ? new List<string> { mn.Name } : (a.Get("method")?.Strings().ToList() ?? new List<string>());
                foreach (var s in selectors)
                {
                    string mapped = MapSelector(c, s);
                    h.Selectors.Add(mapped);
                    var (keys, pretty) = ResolveSelector(c, mapped, c.MixinTargets);
                    foreach (var k in keys) h.TargetKeys.Add(k);
                    h.TargetPretty.AddRange(pretty);
                }
                h.Cancellable = a.Get("cancellable") is { } cv && cv.Num != 0;
                foreach (var at in (a.Get("at")?.Annotations() ?? Enumerable.Empty<Annotation>()).Take(1))
                {
                    h.AtValue = at.Get("value")?.Str ?? "";
                    string target = at.Get("target")?.Str ?? "";
                    if (target.Length > 0)
                    {
                        string mapped = MapSelector(c, target);
                        if (h.AtValue == "NEW" && mapped.StartsWith('L') && mapped.EndsWith(';'))
                        {
                            foreach (var k in Names.ClassKeys(mapped[1..^1])) h.AtKeys.Add(k);
                            h.AtPretty.Add("new " + Names.ShortClass(mapped[1..^1]));
                        }
                        else
                        {
                            var (keys, pretty) = ResolveSelector(c, mapped, c.MixinTargets);
                            foreach (var k in keys) h.AtKeys.Add(k);
                            h.AtPretty.AddRange(pretty);
                        }
                    }
                }
                foreach (var cst in a.Get("constant")?.Annotations() ?? Enumerable.Empty<Annotation>())
                {
                    if (cst.Get("doubleValue") is { } dv) h.Constants.Add(BitConverter.Int64BitsToDouble(dv.Num));
                    if (cst.Get("floatValue") is { } fv) h.Constants.Add(BitConverter.Int32BitsToSingle((int)fv.Num));
                    if (cst.Get("intValue") is { } iv) h.Constants.Add((int)iv.Num);
                }
                c.Hooks.Add(h);
                Hooks.Add(h);
                mn.AsHook ??= h;
            }
    }

    // ------------------------------------------------------------------ расшифровка строк

    public int DecryptedCount;

    private void DecryptStrings()
    {
        var emu = new StringEmu(
            (o, n, d) => Classes.TryGetValue(o, out var c) && c.BySig.TryGetValue(n + d, out var mn) && mn.Mi.IsStatic ? mn.Mi : null,
            o => Classes.ContainsKey(o), TimeSpan.FromSeconds(5))
        { FindClass = o => Classes.TryGetValue(o, out var c) ? c.Cf : null };

        foreach (var c in Classes.Values)
        {
            if (c.IsLibrary || IsLibraryJar || emu.TimeUp) continue;
            // таблицы строк в статических полях
            if (c.BySig.TryGetValue("<clinit>()V", out var clinit) && c.Cf.Fields.Any(f => f.IsStatic && (f.Desc is "Ljava/lang/String;" or "[Ljava/lang/String;" or "[C" or "[I" or "[B" or "[Ljava/lang/Object;")))
            {
                emu.Enter(c.Cf);
                foreach (var s in emu.RunClinit(c.Name, clinit.Mi))
                    if (StringEmu.Plausible(s) && !c.Cf.Strings.Contains(s) && !clinit.Decrypted.Contains(s)) clinit.Decrypted.Add(s);
            }
            // места вызова расшифровщиков и сборки строк из массивов
            foreach (var mn in c.Methods)
            {
                if (emu.TimeUp) break;
                if (!LooksLikeStringBuilding(c, mn)) continue;
                emu.Enter(c.Cf);
                foreach (var s in emu.Scan(c.Name, mn.Mi))
                    if (StringEmu.Plausible(s) && !c.Cf.Strings.Contains(s) && !mn.Decrypted.Contains(s)) mn.Decrypted.Add(s);
            }
        }
        DecryptedCount = Classes.Values.Sum(c => c.Methods.Sum(x => x.Decrypted.Count));
        if (emu.TimeUp) Log.Add("расшифровка строк остановлена по времени");
    }

    /// <summary>В методе есть вызов своего статического метода, возвращающего String, или сборка String из массива.</summary>
    private bool LooksLikeStringBuilding(ClassNode c, MethodNode mn)
    {
        foreach (var ins in mn.Mi.Insns)
        {
            if (ins.Op == Bytecode.INVOKESTATIC)
            {
                var r = c.Cf.Member(ins.Operand);
                if (r is not null && r.Desc.EndsWith(")Ljava/lang/String;") && Classes.ContainsKey(r.Owner)) return true;
            }
            else if (ins.Op == Bytecode.INVOKESPECIAL)
            {
                var r = c.Cf.Member(ins.Operand);
                if (r is { Owner: "java/lang/String", Name: "<init>" } && r.Desc.StartsWith("([")) return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ факты класса

    private static readonly string[] NettyHandlers =
    {
        "io/netty/channel/ChannelDuplexHandler", "io/netty/channel/ChannelOutboundHandlerAdapter", "io/netty/channel/ChannelInboundHandlerAdapter",
        "io/netty/channel/SimpleChannelInboundHandler", "io/netty/handler/codec/MessageToByteEncoder", "io/netty/handler/codec/ByteToMessageDecoder",
        "io/netty/handler/codec/MessageToMessageEncoder", "io/netty/handler/codec/MessageToMessageDecoder", "io/netty/channel/ChannelHandlerAdapter",
    };

    private void ClassFacts(ClassNode c)
    {
        string? s = c.Cf.Super;
        int guard = 0;
        while (s is not null && guard++ < 16)
        {
            if (s is "java/lang/ClassLoader" or "java/net/URLClassLoader" or "java/security/SecureClassLoader") c.ExtendsClassLoader = true;
            if (NettyHandlers.Contains(s)) c.IsNettyHandler = true;
            s = Classes.TryGetValue(s, out var sc) ? sc.Cf.Super : null;
        }
        foreach (var f in c.Cf.Fields)
        {
            if (!IsCollectionType(f.Desc)) continue;
            string sig = f.Signature ?? "";
            if (sig.Length == 0) continue;
            foreach (var cls in SigClasses(sig))
            {
                if (IsCollectionType("L" + cls + ";")) continue;
                if (IsPacketClass(cls) || (Classes.TryGetValue(cls, out var w) && w.Cf.Fields.Any(wf => Descriptors.ClassesIn(wf.Desc).Any(IsPacketClass))))
                {
                    c.HeldPacketTypes.Add(IsPacketClass(cls) ? Names.ShortClass(cls) : "Packet");
                    c.PacketCollections.Add($"{f.Name}: {PrettySig(sig)}");
                    break;
                }
            }
        }
    }

    private static readonly Regex SigClassRx = new(@"L([A-Za-z0-9_/$]+)[<;]", RegexOptions.Compiled);

    /// <summary>Все классы в generic-сигнатуре (включая параметры типов): List&lt;Packet&gt; → List, Packet.</summary>
    private static IEnumerable<string> SigClasses(string sig)
    {
        foreach (Match mt in SigClassRx.Matches(sig)) yield return mt.Groups[1].Value;
    }

    private static bool IsCollectionType(string desc) =>
        desc.StartsWith("Ljava/util/") && (desc.Contains("List") || desc.Contains("Queue") || desc.Contains("Deque") || desc.Contains("Map") || desc.Contains("Set") || desc.Contains("Collection"))
        || desc.StartsWith("Lit/unimi/dsi/fastutil/") || desc.StartsWith("Lcom/google/common/collect/");

    public bool IsPacketClass(string cls)
    {
        if (!GameNames.IsGame(cls)) return false;
        foreach (var k in Names.ClassKeys(cls)) if (k == "C:Packet") return true;
        return false;
    }

    private string PrettySig(string sig) => Regex.Replace(sig, @"L([^;<]+)", mm =>
    {
        string n = mm.Groups[1].Value;
        return GameNames.IsGame(n) ? Names.ShortClass(n) : n[(n.LastIndexOf('/') + 1)..];
    }).Replace(";", "");

    // ------------------------------------------------------------------ обход байт-кода

    private void ScanMethod(MethodNode mn)
    {
        var cf = mn.Owner.Cf;
        DecryptedStrings(mn);
        foreach (var cls in Descriptors.ClassesIn(mn.Mi.Desc)) ClassRef(mn, cls);
        foreach (var ins in mn.Mi.Insns)
        {
            byte op = ins.Op;
            if (op is Bytecode.INVOKEVIRTUAL or Bytecode.INVOKESPECIAL or Bytecode.INVOKESTATIC or Bytecode.INVOKEINTERFACE)
            {
                var r = cf.Member(ins.Operand);
                if (r is not null) MemberRef(mn, r, false);
            }
            else if (op is Bytecode.GETFIELD or Bytecode.GETSTATIC or Bytecode.PUTFIELD or Bytecode.PUTSTATIC)
            {
                var r = cf.Member(ins.Operand);
                if (r is not null) MemberRef(mn, r, op is Bytecode.PUTFIELD or Bytecode.PUTSTATIC);
            }
            else if (op == Bytecode.INVOKEDYNAMIC)
            {
                foreach (var h in cf.IndyRefs(ins.Operand)) MemberRef(mn, h, false);
            }
            else if (op is Bytecode.NEW or Bytecode.CHECKCAST or Bytecode.INSTANCEOF or Bytecode.ANEWARRAY)
            {
                string cn = cf.ClassName(ins.Operand);
                if (cn.StartsWith('[')) cn = Descriptors.ClassOfDescriptor(cn) ?? "";
                if (cn.Length > 0) ClassRef(mn, cn);
            }
            else if (op is Bytecode.LDC or Bytecode.LDC_W or Bytecode.LDC2_W)
            {
                switch (cf.TagAt(ins.Operand))
                {
                    case CpTag.String:
                        string s = cf.LdcString(ins.Operand) ?? "";
                        if (s.Length > 0)
                        {
                            if (mn.Strings.Count < 400) mn.Strings.Add(s);
                            foreach (var sa in Vocab.Strings)
                                if (sa.Rx.IsMatch(s)) mn.Hit(sa.Id, "\"" + Trunc(s, 120) + "\"");
                        }
                        break;
                    case CpTag.Class:
                        ClassRef(mn, cf.ClassName(ins.Operand));
                        break;
                    case CpTag.Double: case CpTag.Float: case CpTag.Integer:
                        double d = cf.LdcDouble(ins.Operand);
                        if (!double.IsNaN(d) && mn.Doubles.Count < 200) mn.Doubles.Add(d);
                        break;
                }
            }
        }
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private void DecryptedStrings(MethodNode mn)
    {
        foreach (var s in mn.Decrypted)
        {
            if (mn.Strings.Count < 600) mn.Strings.Add(s);
            foreach (var sa in Vocab.Strings)
                if (sa.Rx.IsMatch(s)) mn.Hit(sa.Id, "\"" + Trunc(s, 120) + "\" (расшифровано)");
        }
    }

    private void ClassRef(MethodNode mn, string cls)
    {
        if (cls.StartsWith('[')) { var el = Descriptors.ClassOfDescriptor(cls); if (el is null) return; cls = el; }
        if (Classes.ContainsKey(cls)) return;
        if (GameNames.IsGame(cls))
        {
            foreach (var k in Names.ClassKeys(cls))
                foreach (var a in Vocab.AtomsOf(k)) mn.Hit(a, Names.PrettyClass(cls));
            foreach (var a in Vocab.AtomsOf("C=" + Names.ShortClass(cls))) mn.Hit(a, Names.PrettyClass(cls));
        }
        else
        {
            foreach (var a in Vocab.AtomsOf("JC:" + cls)) mn.Hit(a, cls.Replace('/', '.'));
        }
    }

    private void MemberRef(MethodNode mn, MemberRef r, bool write)
    {
        string owner = r.Owner;
        if (owner.StartsWith('[')) return;
        if (Classes.TryGetValue(owner, out var own))
        {
            if (_accessors.TryGetValue(owner + "." + r.Name + r.Desc, out var acc))
            {
                foreach (var k in acc.Keys) foreach (var a in Vocab.AtomsOf(k)) mn.Hit(a, acc.Pretty);
                return;
            }
            var callee = FindOwnMethod(own, r.Name, r.Desc);
            if (callee is not null && IsShadow(callee)) callee = null;
            if (callee is not null && callee != mn) { if (!mn.Callees.Contains(callee)) mn.Callees.Add(callee); return; }
            if (callee is null)
            {
                // член игры, вызванный через свой подкласс или shadow-член mixin'а
                foreach (var go in GameOwners(owner))
                    GameMember(mn, go, r.Name, write);
                if (GameNames.IsIntermediaryMember(r.Name) && GameOwners(owner).Count == 0) GameMember(mn, "", r.Name, write);
            }
            return;
        }
        if (GameNames.IsGame(owner)) { GameMember(mn, owner, r.Name, write); return; }

        // JDK и сторонние библиотеки
        string key = "J:" + owner + "." + r.Name;
        foreach (var a in Vocab.AtomsOf(key)) mn.Hit(a, owner.Replace('/', '.') + "." + r.Name);
        foreach (var a in Vocab.AtomsOf("JC:" + owner)) mn.Hit(a, owner.Replace('/', '.'));
        if (r.Name is "defineClass" or "defineHiddenClass" or "defineAnonymousClass")
            foreach (var a in Vocab.AtomsOf("J:*.defineClass")) mn.Hit(a, owner.Replace('/', '.') + "." + r.Name);
    }

    private void GameMember(MethodNode mn, string owner, string name, bool write)
    {
        var keys = Names.MemberKeys(owner, name);
        string? pretty = null;
        // обращение именно к локальному игроку (LocalPlayer / ClientPlayerEntity): «LP:член»
        if (owner.Length > 0 && Names.ShortClass(owner) is "LocalPlayer" or "ClientPlayerEntity")
            foreach (var k in keys)
            {
                int dot = k.IndexOf('.');
                if (dot < 0 || !(k.StartsWith("LocalPlayer.") || k.StartsWith("ClientPlayerEntity."))) continue;
                string lp = "LP:" + k[(dot + 1)..];
                foreach (var a in Vocab.AtomsOf(lp)) mn.Hit(a, (pretty ??= Names.Pretty(owner, name)) + " [локальный игрок]");
                if (write) foreach (var a in Vocab.AtomsOf(lp + "=")) mn.Hit(a, (pretty ??= Names.Pretty(owner, name)) + " = … [локальный игрок]");
            }
        foreach (var k in keys)
        {
            foreach (var a in Vocab.AtomsOf(k)) mn.Hit(a, pretty ??= Names.Pretty(owner, name));
            if (write) foreach (var a in Vocab.AtomsOf(k + "=")) mn.Hit(a, (pretty ??= Names.Pretty(owner, name)) + " = …");
        }
        if (owner.Length > 0 && name != "<init>")
            foreach (var k in Names.ClassKeys(owner))
                if (k == "C:Packet") foreach (var a in Vocab.AtomsOf(k)) mn.Hit(a, Names.PrettyClass(owner));
    }

    private static bool IsShadow(MethodNode m) =>
        m.Owner.IsMixin && (m.Mi.IsAbstract || m.Mi.Annotations.Any(a => a.TypeName == "org/spongepowered/asm/mixin/Shadow"));

    public MethodNode? FindOwnMethod(ClassNode c, string name, string desc)
    {
        ClassNode? cur = c;
        int guard = 0;
        while (cur is not null && guard++ < 16)
        {
            if (cur.BySig.TryGetValue(name + desc, out var m)) return m;
            if (cur.Cf.Super is null || !Classes.TryGetValue(cur.Cf.Super, out cur)) break;
        }
        // интерфейсы по умолчанию
        foreach (var i in c.Cf.Interfaces)
            if (Classes.TryGetValue(i, out var ic) && ic.BySig.TryGetValue(name + desc, out var dm)) return dm;
        return null;
    }

    private void ComputeClosure(MethodNode root)
    {
        var acc = root.Direct;
        if (root.Callees.Count > HubLimit) { root.Closure = acc; return; }   // сам диспетчер: его вызовы проверяются по отдельности
        var seen = new HashSet<MethodNode> { root };
        var frontier = new List<MethodNode> { root };
        for (int d = 0; d < ClosureDepth && frontier.Count > 0; d++)
        {
            var next = new List<MethodNode>();
            foreach (var m in frontier)
            {
                if (m != root && m.Callees.Count > HubLimit) continue;      // диспетчер: не склеиваем всё, что он вызывает
                foreach (var c in m.Callees)
                    if (seen.Add(c)) { acc.Or(c.Direct); next.Add(c); }
            }
            frontier = next;
            if (seen.Count > 400) break;
        }
        root.Closure = acc;
    }

    /// <summary>Сам метод и все методы мода, достижимые из него (с теми же ограничениями, что и замыкание).</summary>
    public List<MethodNode> ClosureMethods(MethodNode root)
    {
        var seen = new List<MethodNode> { root };
        var set = new HashSet<MethodNode> { root };
        var frontier = new List<MethodNode> { root };
        for (int d = 0; d < ClosureDepth && frontier.Count > 0; d++)
        {
            var next = new List<MethodNode>();
            foreach (var mm in frontier)
            {
                if (mm.Callees.Count > HubLimit) continue;
                foreach (var c in mm.Callees) if (set.Add(c)) { seen.Add(c); next.Add(c); }
            }
            frontier = next;
        }
        return seen;
    }

    /// <summary>Цепочка вызовов от метода до того, кто напрямую обращается к атому, и сами обращения.</summary>
    public (List<MethodNode> Path, List<string> Refs) Trace(MethodNode root, int atom)
    {
        var prev = new Dictionary<MethodNode, MethodNode?> { [root] = null };
        var q = new Queue<(MethodNode M, int D)>();
        q.Enqueue((root, 0));
        while (q.Count > 0)
        {
            var (m, d) = q.Dequeue();
            if (m.Direct.Has(atom))
            {
                var path = new List<MethodNode>();
                for (MethodNode? x = m; x is not null; x = prev[x]) path.Add(x);
                path.Reverse();
                return (path, m.Hits.TryGetValue(atom, out var l) ? l : new List<string>());
            }
            if (d >= ClosureDepth || m.Callees.Count > HubLimit) continue;
            foreach (var c in m.Callees)
                if (!prev.ContainsKey(c)) { prev[c] = m; q.Enqueue((c, d + 1)); }
        }
        return (new List<MethodNode>(), new List<string>());
    }

    public string Label(MethodNode m)
    {
        string desc = Descriptors.PrettyMethodDesc(m.Mi.Desc, c => GameNames.IsGame(c) ? Names.ShortClass(c) : c);
        return $"{m.Owner.SimpleName}.{m.Name}{desc}";
    }

    /// <summary>Описание атома в методе: «цель под прицелом: Minecraft.hitResult (… ) — в onTick → findTarget».</summary>
    public string Explain(MethodNode root, int atom)
    {
        var (path, refs) = Trace(root, atom);
        if (path.Count == 0) return Vocab.Title(atom);
        string via = path.Count > 1 ? "  ⟵ " + string.Join(" → ", path.Select(p => p.Owner == root.Owner ? p.Name : p.Owner.SimpleName + "." + p.Name)) : "";
        return $"{Vocab.Title(atom)}: {string.Join("; ", refs.Take(3))}{via}";
    }
}
