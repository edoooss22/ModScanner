using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner.Analysis;

internal enum Verdict { Clean, Verified, Review, Suspicious, Cheat }

/// <summary>Итог по одному jar (сам мод или вложенный).</summary>
internal sealed class UnitResult
{
    public ModUnit Unit = null!;
    public List<Finding> Findings = new();
    public double Score;
    public Verdict Verdict;
    public bool DeepScanned;
    public List<string> Signals = new();
    public int ClassCount, MixinCount, HookCount;
    public List<string> Hooks = new();
    public List<string> Decrypted = new();

    public int Count(Severity s) => Findings.Count(f => f.Severity == s);
}

/// <summary>Итог по одному файлу мода целиком (с учётом вложенных jar).</summary>
internal sealed class FileResult
{
    public int Index;
    public string Path = "";
    public string FileName = "";
    public ModUnit Root = null!;
    public List<UnitResult> Units = new();
    public Verdict Verdict;
    public List<string> Signals = new();
    public TimeSpan Elapsed;
    public string ReportFile = "";

    public UnitResult RootUnit => Units[0];
    public IEnumerable<Finding> AllFindings => Units.SelectMany(u => u.Findings);
}

internal sealed class Scanner
{
    private readonly GameNames _names;
    private readonly Modrinth _mr;
    public readonly List<string> Log = new();

    // сигналы целевых функций — именно они определяют вердикт «чит»
    public static readonly string[] FunctionSignals =
    {
        "KillAura", "TriggerBot", "HitBox", "Reach", "AimAssist", "Внешняя авторизация", "Загрузка кода из сети", "Скачивание и запуск файла",
        "Кража токена сессии", "Кража данных", "Отправка данных на вебхук", "FakeLag / Blink", "PingSpoof", "Задержка входящих пакетов",
    };

    public Scanner(GameNames names, Modrinth mr) { _names = names; _mr = mr; }

    /// <summary>Отладка: печатать модель классов, в имени которых есть эта подстрока.</summary>
    public string? Explain;

    private void DumpModel(ModModel m)
    {
        foreach (var c in m.Classes.Values.Where(c => c.Name.Contains(Explain!, StringComparison.OrdinalIgnoreCase)).Take(20))
        {
            Console.WriteLine();
            Console.WriteLine($"=== {c.Name}  super={c.Cf.Super} mixin={c.IsMixin} [{string.Join(",", c.MixinTargets)}] lib={c.IsLibrary} netty={c.IsNettyHandler}");
            foreach (var p in c.PacketCollections) Console.WriteLine("  packets field: " + p);
            foreach (var f in c.Cf.Fields) Console.WriteLine($"  field {f.Name}: {f.Desc} sig={f.Signature}");
            foreach (var h in c.Hooks) Console.WriteLine("  hook " + h.Describe() + "  changes=" + h.ChangesValue);
            foreach (var mn in c.Methods)
            {
                foreach (var d in mn.Decrypted) Console.WriteLine($"  decrypted in {mn.Name}: {d}");
                if (mn.Direct.IsEmpty && mn.Callees.Count == 0) continue;
                Console.WriteLine($"  {mn.Name}{mn.Mi.Desc}  callees={mn.Callees.Count}");
                Console.WriteLine("     direct: " + string.Join(", ", mn.Direct.Ids().Select(i => Vocab.All[i].Name)));
                Console.WriteLine("     closure: " + string.Join(", ", mn.Closure.Ids().Select(i => Vocab.All[i].Name)));
            }
        }
    }

    public FileResult Scan(string path, byte[] bytes)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var root = ModUnit.Load(path, bytes);
        var fr = new FileResult { Path = path, FileName = System.IO.Path.GetFileName(path), Root = root };
        var units = root.SelfAndNested().ToList();

        // 1. идентичность по хешу — пакетно для всего дерева
        var byHash = _mr.LookupHashes(units.Select(u => u.Sha1));
        foreach (var u in units) if (byHash.TryGetValue(u.Sha1, out var r)) u.Modrinth = r;

        // 2. сверка корня с оригиналом (до анализа вложенных — помечает подменённые вложенные jar)
        var rootFindings = new List<Finding>();
        if (!root.Verified)
        {
            var rctx = new ScanContext { Unit = root, Names = _names };
            try { OriginDiffAnalyzer.Run(rctx, _mr); } catch (Exception ex) { Log.Add("origindiff: " + ex.Message); }
            rootFindings = rctx.Findings;
        }

        // 3. глубокая проверка каждого jar. Подтверждённые Modrinth не проверяются на подмену (файл авторский),
        // но функции ищутся всегда: Modrinth подтверждает подлинность файла, а не отсутствие читов в нём.
        foreach (var u in units)
        {
            var ur = new UnitResult { Unit = u };
            bool verified = u.Verified || (u.Parent is not null && AncestorVerified(u) && !u.Tampered);
            var ctx = new ScanContext { Unit = u, Names = _names, Verified = verified };
            try
            {
                ctx.Model = ModModel.Build(u, _names);
                if (Explain is not null) DumpModel(ctx.Model);
                ur.ClassCount = ctx.Model.Classes.Count;
                ur.MixinCount = ctx.Model.Classes.Values.Count(c => c.IsMixin);
                ur.HookCount = ctx.Model.Hooks.Count;
                ur.Hooks = ctx.Model.Hooks.Take(400).Select(h => h.Describe()).ToList();
                ur.Decrypted = ctx.Model.Classes.Values.SelectMany(c => c.Methods.SelectMany(x => x.Decrypted.Select(d => $"{c.SimpleName}.{x.Name}:  {d}"))).Take(3000).ToList();
                if (u == root) ctx.Findings.AddRange(rootFindings);
                bool library = u.IsLibrary;
                foreach (var a in Analyzers(verified, library))
                    try { a.Run(ctx); } catch (Exception ex) { Log.Add($"{u.DisplayName} / {a.Name}: {ex.Message}"); }
            }
            catch (Exception ex) { Log.Add($"{u.DisplayName}: модель не построена: {ex.Message}"); }
            ur.Findings = Consolidate(ctx.Findings);
            ur.DeepScanned = true;
            u.DeepScanned = true;
            Classify(ur, verified);
            fr.Units.Add(ur);
            // освобождаем тяжёлые данные вложенных jar (модель больше не нужна)
            ctx.Model = null!;
        }

        ReviewOriginDiff(fr);
        fr.Verdict = fr.Units.Select(u => u.Verdict).DefaultIfEmpty(Verdict.Clean).Max();
        fr.Signals = fr.Units.SelectMany(u => u.Signals).Distinct().OrderBy(s => Array.IndexOf(FunctionSignals, s) is var i && i >= 0 ? i : 99).ToList();
        sw.Stop();
        fr.Elapsed = sw.Elapsed;
        return fr;
    }

    private static readonly HashSet<string> FunctionCategories = new() { "Бой", "Авторизация", "Пакеты" };

    /// <summary>
    /// «Файл отличается от оригинала» — ещё не чит: бывают сборки с CurseForge и перекомпиляции. Критично, только если
    /// в добавленных/изменённых классах (или в подменённых вложенных jar) найдены целевые функции или опасные возможности.
    /// </summary>
    private void ReviewOriginDiff(FileResult fr)
    {
        var rootUr = fr.Units[0];
        var diff = fr.Root.Diff;
        foreach (var f in rootUr.Findings.Where(x => x.Analyzer == "Оригинал" && x.Signal == "Правка чистого мода").ToList())
        {
            var focus = diff?.FocusClasses ?? new HashSet<string>();
            var proof = rootUr.Findings.Where(x => FunctionCategories.Contains(x.Category) && x.Severity >= Severity.High && InFocus(x.Location, focus)).ToList();
            proof.AddRange(fr.Units.Skip(1).Where(ur => ur.Unit.Tampered).SelectMany(ur => ur.Findings)
                .Where(x => FunctionCategories.Contains(x.Category) && x.Severity >= Severity.High));
            if (proof.Count > 0)
            {
                f.EvLines("Что найдено в изменённом коде", proof.Select(x => $"[{x.Signal}] {x.Title}").Distinct().Take(20));
                continue;
            }
            int added = diff?.AddedClasses.Count ?? 0, changed = diff?.ChangedClasses.Count ?? 0, total = Math.Max(1, fr.Root.Classes.Count);
            bool nested = (diff?.NestedChanged.Count ?? 0) + (diff?.NestedAdded.Count ?? 0) > 0;
            if (!nested && added == 0 && changed > total / 2)
            {
                f.Severity = Severity.Low; f.Weight = 1; f.Signal = null;
                f.Title = "Файл отличается от релиза на Modrinth — похоже на другую сборку того же мода";
                f.Why = "Классы не добавлены, но изменена большая часть существующих — так выглядит перекомпиляция (сборка с CurseForge, другая версия игры с тем же номером). Читерских функций в изменённом коде не найдено.";
            }
            else
            {
                f.Severity = Severity.Medium; f.Weight = 5;
                f.Title = f.Title.Replace("Файл отличается от оригинала", "Файл отличается от релиза");
                f.Why = "Файл отличается от релиза на Modrinth с тем же номером версии. Читерских функций в изменённом коде не найдено, но добавленные и изменённые классы стоит просмотреть: возможно, это другая сборка или более новая версия с неправленым номером.";
            }
        }
        Classify(rootUr, rootUr.Unit.Verified);
    }

    private static bool InFocus(string location, HashSet<string> focus)
    {
        if (location.Length == 0 || focus.Count == 0) return false;
        string loc = location.Replace('.', '/');
        return focus.Contains(loc) || focus.Any(c => c.StartsWith(loc + "$", StringComparison.Ordinal) || loc.StartsWith(c + "$", StringComparison.Ordinal));
    }

    private static bool AncestorVerified(ModUnit u)
    {
        for (var p = u.Parent; p is not null; p = p.Parent) if (p.Verified) return true;
        return false;
    }

    private static IEnumerable<IAnalyzer> Analyzers(bool verified, bool library)
    {
        yield return new CombatAnalyzer();
        yield return new PacketAnalyzer();
        yield return new AuthAnalyzer();
        if (library) yield break;                 // вложенная библиотека без метаданных мода (kotlin, jruby, imgui…)
        yield return new SignatureAnalyzer();
        if (!verified)
        {
            yield return new PackagingAnalyzer();
            yield return new MetadataAnalyzer();
            yield return new ObfuscationAnalyzer();
        }
    }

    /// <summary>Склейка: не больше 6 находок одного вида; названия, подтверждённые поведением, — в справку.</summary>
    private static List<Finding> Consolidate(List<Finding> fs)
    {
        // «пустой» крючок (логика вырезана) + модуль с тем же названием — две независимые улики одной функции
        foreach (var inert in fs.Where(f => f.Tags.Contains("inert")).ToList())
        {
            var named = fs.FirstOrDefault(f => f.Analyzer == "Названия" && f.Signal == inert.Signal && f.Severity >= Severity.Medium);
            if (named is null || fs.Any(f => f != inert && f.Analyzer != "Названия" && f.Signal == inert.Signal && f.Severity == Severity.Critical)) continue;
            inert.Severity = Severity.Critical;
            inert.Weight = 26;
            inert.Title = "HitBox — модуль «HitBox» есть, а в расчёт хитбокса встроена инъекция (логика вырезана или подгружается отдельно)";
            inert.EvLines("Модуль по названию", named.Evidence.Select(e => e.Text));
        }
        var confirmed = fs.Where(f => f.Analyzer != "Названия" && f.Signal is not null && f.Severity >= Severity.High).Select(f => f.Signal!).ToHashSet();
        foreach (var f in fs.Where(f => f.Analyzer == "Названия" && f.Signal is not null && confirmed.Contains(f.Signal!)))
        {
            f.Severity = Severity.Info;
            f.Weight = 0;
            f.Title += " — подтверждено поведением";
        }
        var res = new List<Finding>();
        foreach (var g in fs.GroupBy(f => (f.Signal ?? f.Title, f.Severity, f.Analyzer)))
        {
            var list = g.ToList();
            res.AddRange(list.Take(6));
            if (list.Count > 6)
                res.Add(new Finding
                {
                    Severity = g.Key.Severity, Category = list[0].Category, Analyzer = list[0].Analyzer, Weight = 0, Signal = list[0].Signal,
                    Title = $"…и ещё {list.Count - 6} мест(а) того же вида ({list[0].Signal ?? list[0].Category})",
                    Why = "Однотипные находки свёрнуты, чтобы не загромождать отчёт.",
                }.EvLines("Где ещё", list.Skip(6).Take(60).Select(x => x.Title)));
        }
        return res;
    }

    private static void Classify(UnitResult ur, bool verified)
    {
        ur.Score = ur.Findings.Sum(f => f.Weight);
        ur.Signals = ur.Findings.Where(f => f.Signal is not null && f.Severity >= Severity.High)
                                .OrderByDescending(f => f.Severity).Select(f => f.Signal!).Distinct().ToList();
        // вердикт — по наибольшей значимости находок, а не по сумме: десяток слабых признаков не складывается в «чит»
        int crit = ur.Count(Severity.Critical), high = ur.Count(Severity.High), med = ur.Count(Severity.Medium);
        ur.Verdict = crit > 0 ? Verdict.Cheat
                   : high > 0 ? Verdict.Suspicious
                   : med > 0 ? Verdict.Review
                   : verified ? Verdict.Verified
                   : Verdict.Clean;
    }
}
