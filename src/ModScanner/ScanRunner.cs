using System.Text;
using ModScanner.Analysis;
using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner;

internal sealed class ScanOptions
{
    public string OutDir = Path.Combine(AppContext.BaseDirectory, "reports");
    public string CacheDir = Path.Combine(AppContext.BaseDirectory, "cache");
    public bool Offline;
    public string? Explain;
}

/// <summary>Ход проверки: этап, номер файла, текущий файл и (после проверки файла) его результат.</summary>
internal sealed class ScanProgress
{
    public string Stage = "";
    public int Done, Total;
    public string File = "";
    public FileResult? Result;
    public string? Error;
}

internal sealed class ScanOutcome
{
    public List<FileResult> Results = new();
    public string SummaryPath = "", JsonPath = "", DetailDir = "";
    public List<string> Log = new();
    public bool Cancelled;
}

/// <summary>Прогресс, вызывающий обработчик сразу в том же потоке (для консоли — сохраняет порядок вывода).</summary>
internal sealed class SyncProgress<T> : IProgress<T>
{
    private readonly Action<T> _a;
    public SyncProgress(Action<T> a) { _a = a; }
    public void Report(T value) => _a(value);
}

/// <summary>Проверка набора jar и запись отчётов — общая для консоли и окна.</summary>
internal static class ScanRunner
{
    private static GameNames? _names;
    private static readonly object _lock = new();

    public static GameNames Names()
    {
        lock (_lock) return _names ??= GameNames.LoadEmbedded();
    }

    public static ScanOutcome Run(IReadOnlyList<string> jars, ScanOptions o, IProgress<ScanProgress>? progress, CancellationToken ct = default)
    {
        var outcome = new ScanOutcome();
        Directory.CreateDirectory(o.OutDir);
        progress?.Report(new ScanProgress { Stage = "Загрузка таблицы имён игры", Total = jars.Count });
        var names = Names();
        var mr = new Modrinth(o.CacheDir, o.Offline);
        var scanner = new Scanner(names, mr) { Explain = o.Explain };

        for (int i = 0; i < jars.Count; i++)
        {
            if (ct.IsCancellationRequested) { outcome.Cancelled = true; break; }
            string jar = jars[i];
            progress?.Report(new ScanProgress { Stage = "Проверка", Done = i, Total = jars.Count, File = jar });
            FileResult? fr = null;
            string? error = null;
            try
            {
                var bytes = File.ReadAllBytes(jar);
                fr = scanner.Scan(jar, bytes);
                fr.Index = outcome.Results.Count + 1;
                outcome.Results.Add(fr);
            }
            catch (Exception ex) { error = ex.Message; }
            progress?.Report(new ScanProgress { Stage = "Проверка", Done = i + 1, Total = jars.Count, File = jar, Result = fr, Error = error });
        }
        mr.SaveCache();

        progress?.Report(new ScanProgress { Stage = "Запись отчёта", Done = outcome.Results.Count, Total = jars.Count });
        WriteReports(outcome, o);
        outcome.Log.AddRange(scanner.Log.Concat(mr.Log));
        return outcome;
    }

    private static void WriteReports(ScanOutcome outcome, ScanOptions o)
    {
        var results = outcome.Results;
        string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string detailName = $"modscan-{stamp}";
        outcome.DetailDir = Path.Combine(o.OutDir, detailName);
        Directory.CreateDirectory(outcome.DetailDir);
        outcome.SummaryPath = Path.Combine(o.OutDir, $"modscan-{stamp}.html");
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fr in results)
        {
            string safe = $"{fr.Index:D2}-{SafeName(fr.FileName)}";
            while (!used.Add(safe)) safe += "_";
            fr.ReportFile = Path.Combine(outcome.DetailDir, safe + ".html");
        }
        File.WriteAllText(outcome.SummaryPath, HtmlReport.RenderSummary(results, o.Offline, detailName), Encoding.UTF8);
        outcome.JsonPath = Path.Combine(o.OutDir, $"modscan-{stamp}.json");
        File.WriteAllText(outcome.JsonPath, HtmlReport.RenderJson(results, o.Offline), new UTF8Encoding(false));
        var ordered = results.OrderBy(r => Rank(r.Verdict)).ThenBy(r => r.FileName, StringComparer.OrdinalIgnoreCase).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            var fr = ordered[i];
            File.WriteAllText(fr.ReportFile, HtmlReport.RenderFile(fr, o.Offline, "../" + Path.GetFileName(outcome.SummaryPath),
                i > 0 ? ordered[i - 1] : null, i + 1 < ordered.Count ? ordered[i + 1] : null, detailName), Encoding.UTF8);
        }
    }

    public static int Rank(Verdict v) => v switch { Verdict.Cheat => 0, Verdict.Suspicious => 1, Verdict.Review => 2, Verdict.Clean => 3, _ => 4 };

    public static string VerdictText(Verdict v) => v switch
    {
        Verdict.Cheat => "ЧИТ", Verdict.Suspicious => "ПОДОЗРИТЕЛЬНО", Verdict.Review => "ТРЕБУЕТ ПРОВЕРКИ",
        Verdict.Verified => "ПОДТВЕРЖДЁН MODRINTH", _ => "ЧИСТО",
    };

    /// <summary>Все .jar в указанных файлах и папках (рекурсивно).</summary>
    public static List<string> CollectJars(IEnumerable<string> inputs, Action<string>? skipped = null)
    {
        var jars = new List<string>();
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var inp in inputs)
        {
            if (Directory.Exists(inp))
                jars.AddRange(Directory.EnumerateFiles(inp, "*.jar", opts));
            else if (File.Exists(inp) && inp.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                jars.Add(inp);
            else skipped?.Invoke(inp);
        }
        return jars.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static readonly string[] Translit =
    {
        "a", "b", "v", "g", "d", "e", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p", "r", "s", "t", "u", "f", "h", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya",
    };

    /// <summary>Имя файла отчёта: только ASCII (кириллица транслитерируется), чтобы ссылки работали в любом браузере и пути.</summary>
    private static string SafeName(string name)
    {
        var sb = new StringBuilder();
        foreach (char ch in Path.GetFileNameWithoutExtension(name))
        {
            char c = char.ToLowerInvariant(ch);
            if (c == 'ё') sb.Append("e");
            else if (c >= 'а' && c <= 'я') sb.Append(Translit[c - 'а']);
            else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch is '-' or '.') sb.Append(ch);
            else sb.Append('_');
        }
        string s = sb.ToString();
        return s.Length > 60 ? s[..60] : s;
    }
}
