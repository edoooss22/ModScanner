using System.IO.Compression;
using System.Reflection;

namespace ModScanner.Core;

/// <summary>
/// Таблица имён игры, общая для всех версий, которые встречаются у модов Fabric 1.21+:
///   * intermediary (class_310 / method_1536 / field_1765) — моды 1.21.x в продакшене;
///   * имена Mojang (Minecraft / startAttack / hitResult) — моды под 26.x (игра без обфускации) и NeoForge;
///   * Yarn (MinecraftClient / doAttack / crosshairTarget) — для отчёта и для старых членов.
/// Любая ссылка из байт-кода сводится к набору ключей «ПростоеИмяКласса.член» по всей цепочке
/// предков владельца — так правило «Entity.getBoundingBox» срабатывает и на LocalPlayer.getBoundingBox,
/// и на class_1297.method_5829, и на ссылку из mixin-класса, у которого владелец — сам mixin.
/// Промежуточные имена мод переименовать не может (иначе не свяжется с игрой) — на этом держится
/// устойчивость к обфускации.
/// </summary>
internal sealed class GameNames
{
    private readonly Dictionary<string, string> _clsMoj = new(StringComparer.Ordinal);    // class_310 → net/minecraft/client/Minecraft
    private readonly Dictionary<string, string> _clsYarn = new(StringComparer.Ordinal);   // class_310 → net/minecraft/client/MinecraftClient
    private readonly Dictionary<string, string> _yarn2Moj = new(StringComparer.Ordinal);  // yarn full → mojang full
    private readonly Dictionary<string, string> _moj2Yarn = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string MojOwner, string MojName, string YarnOwner, string YarnName)> _mem = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string Super, string[] Ifaces)> _hier = new(StringComparer.Ordinal);
    private readonly HashSet<string> _knownMoj = new(StringComparer.Ordinal);

    private readonly Dictionary<string, string[]> _chainCache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string[]> _keyCache = new(StringComparer.Ordinal);

    public int ClassCount => _clsMoj.Count + _clsYarn.Count(kv => !_clsMoj.ContainsKey(kv.Key));
    public int MemberCount => _mem.Count;

    public static GameNames LoadEmbedded()
    {
        var g = new GameNames();
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("names.tsv.gz")
                      ?? throw new Exception("встроенный ресурс names.tsv.gz не найден");
        using var gz = new GZipStream(s, CompressionMode.Decompress);
        using var r = new StreamReader(gz);
        string? line;
        while ((line = r.ReadLine()) is not null)
        {
            var p = line.Split('\t');
            switch (p[0])
            {
                case "C" when p.Length >= 4:
                    if (p[2].Length > 0) { g._clsMoj[p[1]] = p[2]; g._knownMoj.Add(p[2]); }
                    if (p[3].Length > 0) g._clsYarn[p[1]] = p[3];
                    if (p[2].Length > 0 && p[3].Length > 0) { g._yarn2Moj[p[3]] = p[2]; g._moj2Yarn[p[2]] = p[3]; }
                    break;
                case "M" when p.Length >= 6:
                    g._mem[p[1]] = (p[2], p[3], p[4], p[5]);
                    break;
                case "H" when p.Length >= 4:
                    g._hier[p[1]] = (p[2], p[3].Length == 0 ? Array.Empty<string>() : p[3].Split(','));
                    g._knownMoj.Add(p[1]);
                    break;
            }
        }
        return g;
    }

    public static bool IsGame(string internalName) =>
        internalName.StartsWith("net/minecraft/", StringComparison.Ordinal) || internalName.StartsWith("com/mojang/", StringComparison.Ordinal);

    public static bool IsIntermediaryMember(string name) =>
        name.StartsWith("method_", StringComparison.Ordinal) || name.StartsWith("field_", StringComparison.Ordinal) || name.StartsWith("comp_", StringComparison.Ordinal);

    private static string Simple(string full)
    {
        int i = full.LastIndexOf('/');
        return i >= 0 ? full[(i + 1)..] : full;
    }

    /// <summary>Каноническое (Mojang) полное имя класса игры: class_310 → net/minecraft/client/Minecraft.</summary>
    public string Canon(string gameClass)
    {
        if (_clsMoj.TryGetValue(gameClass, out var m)) return m;
        if (_yarn2Moj.TryGetValue(gameClass, out var y)) return y;
        if (_clsYarn.TryGetValue(gameClass, out var yy)) return yy;          // есть только в Yarn (старый класс)
        // вложенный класс intermediary с неизвестным хвостом: class_310$class_123
        int d = gameClass.IndexOf('$');
        if (d > 0 && _clsMoj.TryGetValue(gameClass[..d], out var outer)) return outer + gameClass[d..];
        return gameClass;
    }

    /// <summary>Класс и все его предки (канонические полные имена), от самого класса вверх.</summary>
    public string[] Chain(string gameClass)
    {
        string c = Canon(gameClass);
        if (_chainCache.TryGetValue(c, out var cached)) return cached;
        var res = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var q = new Queue<string>();
        q.Enqueue(c);
        while (q.Count > 0 && res.Count < 64)
        {
            var x = q.Dequeue();
            if (!seen.Add(x)) continue;
            res.Add(x);
            if (_hier.TryGetValue(x, out var h))
            {
                if (h.Super.Length > 0) q.Enqueue(h.Super);
                foreach (var i in h.Ifaces) q.Enqueue(i);
            }
        }
        var arr = res.ToArray();
        _chainCache[c] = arr;
        return arr;
    }

    /// <summary>
    /// Ключи ссылки на член игры: «Простое.член» (Mojang и Yarn) для владельца и всех его предков.
    /// gameOwner — класс игры, через который идёт ссылка (пустая строка — владелец неизвестен).
    /// </summary>
    public string[] MemberKeys(string gameOwner, string name)
    {
        string ck = gameOwner + "|" + name;
        if (_keyCache.TryGetValue(ck, out var cached)) return cached;
        var ownerChain = gameOwner.Length > 0 ? Chain(gameOwner) : Array.Empty<string>();
        var keys = new HashSet<string>(StringComparer.Ordinal);
        string mojName = name, yarnName = "";
        if (IsIntermediaryMember(name) && _mem.TryGetValue(name, out var mm))
        {
            if (mm.MojName.Length > 0) mojName = mm.MojName;
            yarnName = mm.YarnName;
            if (mm.MojOwner.Length > 0 && mm.MojName.Length > 0)
                foreach (var a in Chain(mm.MojOwner)) keys.Add(Simple(a) + "." + mm.MojName);
            if (mm.YarnOwner.Length > 0 && yarnName.Length > 0) keys.Add(Simple(mm.YarnOwner) + "." + yarnName);
        }
        foreach (var o in ownerChain)
        {
            keys.Add(Simple(o) + "." + mojName);
            if (yarnName.Length > 0)
            {
                string yo = _moj2Yarn.TryGetValue(o, out var yf) ? yf : o;
                keys.Add(Simple(yo) + "." + yarnName);
            }
        }
        var arr = keys.ToArray();
        _keyCache[ck] = arr;
        return arr;
    }

    /// <summary>Ключи класса: «C:Простое» для класса и его предков (Mojang и Yarn).</summary>
    public IEnumerable<string> ClassKeys(string gameClass)
    {
        foreach (var c in Chain(gameClass))
        {
            yield return "C:" + Simple(c);
            if (_moj2Yarn.TryGetValue(c, out var y)) yield return "C:" + Simple(y);
        }
    }

    public string ShortClass(string gameClass) => Simple(Canon(gameClass));

    /// <summary>Читаемое имя члена для отчёта: «MultiPlayerGameMode.attack (yarn: ClientPlayerInteractionManager.attackEntity, method_2918)».</summary>
    public string Pretty(string owner, string name)
    {
        if (IsIntermediaryMember(name) && _mem.TryGetValue(name, out var mm))
        {
            string mo = mm.MojOwner.Length > 0 ? Simple(mm.MojOwner) : ShortClass(owner);
            string mn = mm.MojName.Length > 0 ? mm.MojName : mm.YarnName;
            string yarn = mm.YarnName.Length > 0 ? $"{Simple(mm.YarnOwner)}.{mm.YarnName}" : "";
            return yarn.Length > 0 && yarn != $"{mo}.{mn}" ? $"{mo}.{mn}  (yarn {yarn}, {name})" : $"{mo}.{mn}  ({name})";
        }
        string sc = ShortClass(owner);
        return IsGame(owner) ? $"{sc}.{name}" : $"{Simple(owner)}.{name}";
    }

    public string PrettyClass(string gameClass)
    {
        string canon = Canon(gameClass);
        string s = Simple(canon);
        if (canon != gameClass) return $"{s} ({Simple(gameClass)})";
        return s;
    }

    /// <summary>Разрешение имени члена из Mixin-селектора: yarn-имя → intermediary по классу-цели (для модов без refmap).</summary>
    public string? YarnToIntermediary(string ownerCanon, string yarnMember)
    {
        // медленный путь, вызывается редко (только для mixin-селекторов с читаемыми именами без refmap)
        var chain = Chain(ownerCanon);
        foreach (var (inter, mm) in _mem)
        {
            if (mm.YarnName != yarnMember && mm.MojName != yarnMember) continue;
            foreach (var c in chain)
                if (mm.MojOwner == c || (_yarn2Moj.TryGetValue(mm.YarnOwner, out var ym) && ym == c)) return inter;
        }
        return null;
    }

    public bool IsKnownMojangClass(string internalName) => _knownMoj.Contains(internalName) || _yarn2Moj.ContainsKey(internalName) || _clsMoj.ContainsKey(internalName);
}
