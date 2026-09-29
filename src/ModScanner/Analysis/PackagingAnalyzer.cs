using System.Security.Cryptography;
using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner.Analysis;

/// <summary>
/// Следы ручной пересборки jar. Не требует ни маппингов, ни разбора байт-кода и потому устойчив к
/// любой обфускации: смотрит на сам zip и на согласованность метаданных. Именно так отличается
/// «чистый мод, в который дописали классы» от исходного файла с сайта.
/// </summary>
internal sealed class PackagingAnalyzer : IAnalyzer
{
    public string Name => "Упаковка";

    public void Run(ScanContext ctx)
    {
        var u = ctx.Unit;
        var z = u.Zip;

        // 1. дубликаты имён в центральном каталоге — java берёт последнюю запись, глаз видит первую
        var dups = z.Entries.Where(e => e.Duplicate && !e.IsDirectory).Select(e => e.Name).Distinct().ToList();
        if (dups.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Целостность", Analyzer = Name, Weight = 6, Signal = "Двойная запись в jar",
                Title = $"Повторяющиеся имена в архиве ({dups.Count})",
                Why = "Одно и то же имя встречается в архиве дважды. Загрузчик классов берёт последнюю запись, а распаковщик и глаз — первую: так подменяют класс, оставив на виду безобидный.",
            }.EvLines("Имена", dups.Take(50)));

        // 2. локальный заголовок расходится с центральным каталогом
        var nameMis = z.Entries.Where(e => e.LocalNameMismatch).ToList();
        var sizeMis = z.Entries.Where(e => e.LocalSizeMismatch && !e.IsDirectory).ToList();
        var broken = z.Entries.Where(e => e.LocalHeaderBroken && !e.IsDirectory).ToList();
        if (nameMis.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Целостность", Analyzer = Name, Weight = 6, Signal = "Расхождение заголовков zip",
                Title = $"Имя в локальном заголовке не совпадает с каталогом ({nameMis.Count})",
                Why = "Имя файла в локальном заголовке отличается от имени в центральном каталоге — архив правили побайтово, а не пересобирали.",
            }.EvLines("Записи", nameMis.Take(30).Select(e => $"каталог: {e.Name}  ≠  локально: {e.LocalName}")));
        if (broken.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, Category = "Целостность", Analyzer = Name, Weight = 3,
                Title = $"Битый локальный заголовок ({broken.Count})",
                Why = "У записи не читается локальный заголовок. Бывает при грубой правке архива.",
            }.EvLines("Записи", broken.Take(30).Select(e => e.Name)));

        // 3. хвост за концом архива
        if (z.TrailingBytes > 16)
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1.5,
                Title = $"Данные за концом архива: {z.TrailingBytes} байт",
                Why = "После структуры конца каталога в файле есть лишние байты. Иногда безобидно, иногда — скрытая нагрузка, дописанная к jar.",
            });
        if (z.PrependedBytes > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1,
                Title = $"Данные перед первым заголовком: {z.PrependedBytes} байт",
                Why = "Перед первой записью архива есть данные (самораспаковывающийся заголовок или дописанное содержимое).",
            });

        // 4. временные метки: небольшая группа файлов переставлена намного позже основной массы
        TimestampOutliers(ctx);

        // 5. подпись jar: цифровые отпечатки в манифесте не совпадают с содержимым
        DigestMismatch(ctx);

        // 6. классы под чужим расширением / спрятанные
        var hidden = u.Classes.Where(c => c.HiddenExtension).ToList();
        if (hidden.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Целостность", Analyzer = Name, Weight = 7, Signal = "Скрытый класс",
                Title = $"Файлы классов под чужим расширением ({hidden.Count})",
                Why = "Внутри — байт-код (сигнатура CAFEBABE), но имя не .class. Так класс прячут от беглого осмотра и распаковщика, а мод загружает его вручную.",
            }.EvLines("Записи", hidden.Take(30).Select(c => $"{c.Zip.Name}  →  класс {c.Cf.Name}")));

        // 7. имя класса не совпадает с путём в архиве
        var mism = u.Classes.Where(c => c.NameMismatch && !c.Cf.ParseError && !c.HiddenExtension).ToList();
        if (mism.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, Category = "Целостность", Analyzer = Name, Weight = 3,
                Title = $"Класс лежит не по своему имени ({mism.Count})",
                Why = "Внутреннее имя класса не совпадает с путём в архиве. Штатные сборки так не делают.",
            }.EvLines("Записи", mism.Take(30).Select(c => $"{c.Zip.Name}  →  {c.Cf.Name}")));

        // 8. битые/зашифрованные записи
        if (u.LoadErrors.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1,
                Title = $"Записи, которые не удалось прочитать ({u.LoadErrors.Count})",
                Why = "Часть записей архива не прочитана — шифрование записи zip, неизвестный метод сжатия или повреждение.",
            }.EvLines("Подробности", u.LoadErrors.Take(30)));
    }

    private void TimestampOutliers(ScanContext ctx)
    {
        var files = ctx.Unit.Zip.Entries.Where(e => !e.IsDirectory && e.Timestamp.Year > 1980).ToList();
        if (files.Count < 6) return;
        var groups = files.GroupBy(e => e.TimestampKey).Select(g => (Key: g.Key, When: g.First().Timestamp, Count: g.Count(), Names: g.Select(x => x.Name).ToList())).OrderByDescending(g => g.Count).ToList();
        if (groups.Count < 2) return;
        var main = groups[0];
        // минорные группы, которые заметно новее основной и малы по числу
        var suspicious = groups.Skip(1)
            .Where(g => g.Count <= Math.Max(12, files.Count / 5) && (g.When - main.When).TotalDays > 30)
            .ToList();
        // только те, где среди переставленных есть классы или fabric.mod.json/mixins
        foreach (var g in suspicious)
        {
            var interesting = g.Names.Where(n => n.EndsWith(".class") || n.EndsWith(".json") || n.EndsWith(".jar")).ToList();
            bool touchesCode = g.Names.Any(n => n.EndsWith(".class") || n == "fabric.mod.json" || n.Contains("mixin"));
            if (!touchesCode) continue;
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Целостность", Analyzer = Name, Weight = 8, Signal = "Дозапись в готовый мод",
                Title = $"Группа файлов переставлена позже основной сборки ({g.Count} шт., {g.When:yyyy-MM-dd HH:mm})",
                Why = $"Основная масса файлов ({main.Count} шт.) собрана {main.When:yyyy-MM-dd}, а эта небольшая группа помечена {g.When:yyyy-MM-dd} — на {(g.When - main.When).TotalDays:0} дн. позже. Это почерк подмены: берут готовый чистый мод и дописывают в него свои классы и правят метаданные.",
            }.EvLines("Переставленные записи", g.Names.Take(40)));
        }
    }

    private void DigestMismatch(ScanContext ctx)
    {
        var u = ctx.Unit;
        if (u.ManifestDigests.Count == 0) return;
        var bad = new List<string>();
        int chec0 = 0;
        foreach (var (name, spec) in u.ManifestDigests)
        {
            int c = spec.IndexOf(':');
            if (c < 0) continue;
            string algo = spec[..c], b64 = spec[(c + 1)..];
            var e = u.Zip.FindEffective(name);
            if (e is null) { bad.Add($"{name} — подписан в манифесте, но записи нет"); continue; }
            var data = u.Zip.Read(e);
            if (data is null) continue;
            byte[] h = algo.ToUpperInvariant() switch
            {
                "SHA-256" => SHA256.HashData(data), "SHA-512" => SHA512.HashData(data),
                "SHA1" or "SHA-1" => SHA1.HashData(data), _ => Array.Empty<byte>(),
            };
            if (h.Length == 0) continue;
            chec0++;
            if (!Convert.ToBase64String(h).Equals(b64, StringComparison.Ordinal)) bad.Add($"{name} — {algo} не совпал");
        }
        if (bad.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.High, Category = "Целостность", Analyzer = Name, Weight = 9, Signal = "Нарушена подпись jar",
                Title = $"Содержимое не совпадает с отпечатками в манифесте ({bad.Count})",
                Why = "У jar есть манифест с криптографическими отпечатками записей (признак подписанной сборки), но фактическое содержимое им не соответствует — файл изменили после сборки.",
            }.EvLines("Расхождения", bad.Take(40)));
    }
}
