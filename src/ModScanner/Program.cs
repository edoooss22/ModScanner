using System.Runtime.InteropServices;
using System.Text;
using ModScanner.Analysis;

namespace ModScanner;

internal static class Program
{
    public const string Version = "2.1";

    [STAThread]
    private static int Main(string[] args)
    {
        // без аргументов — окно; с аргументами — консольный режим (как раньше)
        if (args.Length == 0)
        {
            System.Windows.Forms.Application.SetHighDpiMode(System.Windows.Forms.HighDpiMode.PerMonitorV2);
            System.Windows.Forms.Application.EnableVisualStyles();
            System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);
            System.Windows.Forms.Application.Run(new Gui.MainForm());
            return 0;
        }
        if (args[0] == "--snapshot" && args.Length >= 2)
        {
            System.Windows.Forms.Application.SetHighDpiMode(System.Windows.Forms.HighDpiMode.SystemAware);
            System.Windows.Forms.Application.EnableVisualStyles();
            Gui.MainForm.Snapshot(args[1], args.Length >= 3 ? args[2] : null);
            return 0;
        }
        bool ownConsole = !AttachConsole(-1) && AllocConsole();
        return Cli(args, ownConsole);
    }

    private static int Cli(string[] args, bool ownConsole)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        try { Console.Title = "ModScanner"; } catch { }
        Console.WriteLine();

        var inputs = new List<string>();
        var opts = new ScanOptions();
        bool nowait = !ownConsole, open = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out" when i + 1 < args.Length: opts.OutDir = args[++i]; break;
                case "--cache" when i + 1 < args.Length: opts.CacheDir = args[++i]; break;
                case "--offline": opts.Offline = true; break;
                case "--nowait": nowait = true; break;
                case "--open": open = true; break;
                case "--explain" when i + 1 < args.Length: opts.Explain = args[++i]; break;
                case "-h" or "--help" or "/?":
                    Help(); Wait(nowait); return 0;
                default: inputs.Add(args[i]); break;
            }
        }

        var jars = ScanRunner.CollectJars(inputs, s => Console.WriteLine($"Пропущено (не jar и не папка): {s}"));
        if (jars.Count == 0) { Console.WriteLine("Не найдено ни одного .jar. Укажите файл или папку."); Wait(nowait); return 2; }

        ScanOutcome outcome;
        try
        {
            outcome = ScanRunner.Run(jars, opts, new SyncProgress<ScanProgress>(p =>
            {
                if (p.Stage != "Проверка") return;
                if (p.Result is null && p.Error is null) Console.Write($"Проверка {Path.GetFileName(p.File)} … ");
                else if (p.Error is not null) Console.WriteLine("ошибка: " + p.Error);
                else Console.WriteLine(Line(p.Result!));
            }));
        }
        catch (Exception ex) { Console.WriteLine("Ошибка: " + ex.Message); Wait(nowait); return 3; }

        Console.WriteLine();
        Console.WriteLine("Сводка:   " + outcome.SummaryPath);
        Console.WriteLine("JSON:     " + outcome.JsonPath);
        Console.WriteLine("По модам: " + outcome.DetailDir);
        foreach (var l in outcome.Log.Take(15)) Console.WriteLine("  · " + l);

        if (open)
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(outcome.SummaryPath) { UseShellExecute = true }); } catch { }

        int worst = outcome.Results.Select(r => (int)r.Verdict).DefaultIfEmpty(0).Max();
        Wait(nowait);
        return worst >= (int)Verdict.Suspicious ? 1 : 0;
    }

    private static string Line(FileResult fr)
    {
        string sig = fr.Signals.Count > 0 ? " — " + string.Join(", ", fr.Signals) : "";
        var mr = fr.Root.Modrinth;
        if (mr is { Found: true } && mr.FileName.Length > 0 && !string.Equals(mr.FileName, fr.FileName, StringComparison.OrdinalIgnoreCase))
            sig += $"  [переименован; на Modrinth: {mr.ProjectTitle} {mr.VersionNumber} — {mr.FileName}]";
        return $"{ScanRunner.VerdictText(fr.Verdict)}{sig}  ({fr.Elapsed.TotalSeconds:0.0}s)";
    }

    private static void Help() => Console.WriteLine($"""
        ModScanner {Version} — античит-проверка модов Minecraft (Fabric 1.21+, также NeoForge и 26.x).

          ModScanner                    окно: выбрать папку или проверить папку программы
          ModScanner [файлы и папки…]   консоль: проверить указанные jar или все jar в папках
          --out DIR      каталог для HTML-отчётов (по умолчанию reports рядом с exe)
          --cache DIR    каталог кеша Modrinth (ответы и скачанные оригиналы)
          --offline      не обращаться к сети (без Modrinth и сверки с оригиналом)
          --open         открыть сводку в браузере по окончании
          --nowait       не ждать клавишу в конце

        Ищется: KillAura, TriggerBot, HitBox, Reach, AimAssist; внешняя авторизация и загрузка кода с сервера;
        манипуляция пакетами для ухудшения пинга (FakeLag/Blink, PingSpoof, задержка входящих).

        Отчёт: modscan-<время>.html (сводка), папка modscan-<время>/ с отдельной страницей каждого мода
        и modscan-<время>.json (машиночитаемые результаты).
        Коды возврата: 1 — есть подозрительные/читы, 0 — чисто, 2 — нет входных файлов, 3 — ошибка.
        """);

    private static void Wait(bool nowait)
    {
        if (nowait || Console.IsInputRedirected) return;
        Console.WriteLine("\nНажмите любую клавишу…");
        try { Console.ReadKey(true); } catch { }
    }

    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll")] private static extern bool AllocConsole();
}
