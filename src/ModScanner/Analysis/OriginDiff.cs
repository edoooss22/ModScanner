using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner.Analysis;

/// <summary>
/// Сверка с оригиналом. Мод не найден в Modrinth по хешу, но его id указывает на существующий там
/// проект? Скачиваем ту же версию с Modrinth и сравниваем поклассно. Добавленные и изменённые классы —
/// это ровно то, что дописали в чистый мод. Самое наглядное доказательство: «взяли AppleSkin и вшили».
/// </summary>
internal static class OriginDiffAnalyzer
{
    public static void Run(ScanContext ctx, Modrinth mr)
    {
        var u = ctx.Unit;
        if (mr.Offline || u.ModId.Length == 0) return;
        string slug = u.ModId;
        if (slug.Length == 0 || slug == "fabric") return;

        var proj = mr.Project(slug);
        if (proj is null) return;                    // нет такого проекта — сверять не с чем

        var diff = new OriginDiff { ProjectTitle = proj.Value.Title, ProjectSlug = proj.Value.Slug };
        var versions = mr.Versions(proj.Value.Slug, u.Loader.Length > 0 ? u.Loader : "fabric");
        if (versions.Count == 0) { return; }

        // ищем в точности ту версию, что заявлена в fabric.mod.json. Только точное совпадение номера
        // даёт право на вывод «изменённый релиз»: версии на Modrinth неизменны, поэтому другой файл с
        // тем же номером — это правка. Нечёткое совпадение (dev/CI-сборка «+126-main») к такому выводу
        // не ведёт: там расхождение с релизом законно.
        string claimed = u.ModVersion;
        var match = PickCandidate(versions, claimed, u.DisplayName);
        if (match is null)
        {
            diff.ClaimedVersionMissing = true;
            diff.OriginalVersion = claimed;
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Целостность", Analyzer = "Оригинал", Weight = 1,
                Title = $"Заявленной версии {claimed} нет среди релизов проекта «{proj.Value.Title}»",
                Why = $"Файл называет себя «{slug} {claimed}», но у проекта на Modrinth такой версии нет (или номер записан иначе). Сверить с оригиналом не удалось: это может быть сборка с CurseForge, старая удалённая версия или самодельная сборка под чужим именем.",
            }.EvLines("Доступные версии", versions.Take(12).Select(v => v.VersionNumber)));
            u.Diff = diff;
            return;
        }

        diff.OriginalVersion = match.VersionNumber;
        diff.OriginalFile = match.FileName;
        diff.OriginalSha1 = match.Sha1;
        var origBytes = mr.Download(match);
        if (origBytes is null) { diff.Error = "оригинал не скачан"; u.Diff = diff; return; }
        diff.OriginalDownloaded = true;

        ZipReader oz;
        try { oz = new ZipReader(origBytes); } catch { diff.Error = "оригинал не разобран"; u.Diff = diff; return; }

        // поклассная карта оригинала: внутреннее имя → sha1 байткода
        var origClasses = new Dictionary<string, string>(StringComparer.Ordinal);
        var origFiles = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var e in oz.Entries)
        {
            if (e.IsDirectory) continue;
            var d = oz.Read(e);
            if (d is null) continue;
            origFiles[e.Name] = d;
            if (e.Name.EndsWith(".class"))
                origClasses[e.Name] = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(d)).ToLowerInvariant();
        }
        diff.OriginalEntries = oz.Entries.Count(e => !e.IsDirectory);

        // вложенные jar: подмена модуля внутри сборки (fabric-api и т.п.)
        foreach (var n in u.Nested)
        {
            if (!origFiles.TryGetValue(n.EntryPath, out var ob)) { diff.NestedAdded.Add(n.EntryPath); continue; }
            string osha = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(ob)).ToLowerInvariant();
            if (osha != n.Sha1) diff.NestedChanged.Add(n.EntryPath);
        }

        var ourClassEntries = u.Classes.Where(c => !c.HiddenExtension).ToDictionary(c => c.Zip.Name, c => c, StringComparer.Ordinal);
        foreach (var (name, ce) in ourClassEntries)
        {
            if (!origClasses.TryGetValue(name, out var oh)) { diff.Added.Add(name); diff.AddedClasses.Add(ce.Cf.Name); diff.FocusClasses.Add(ce.Cf.Name); }
            else if (oh != ce.Sha1) { diff.Changed.Add(name); diff.ChangedClasses.Add(ce.Cf.Name); diff.FocusClasses.Add(ce.Cf.Name); }
        }
        foreach (var name in origClasses.Keys) if (!ourClassEntries.ContainsKey(name)) diff.Removed.Add(name);

        // изменённые не-классовые ключевые файлы
        foreach (var key in new[] { "fabric.mod.json" }.Concat(u.MixinConfigs.Select(m => m.Path)))
        {
            var our = u.Zip.Read(key);
            if (our is null) continue;
            if (!origFiles.TryGetValue(key, out var orig)) diff.Notes.Add($"{key}: добавлен (в оригинале не было)");
            else if (!orig.AsSpan().SequenceEqual(our)) diff.Notes.Add($"{key}: изменён относительно оригинала");
        }

        u.Diff = diff;

        if (diff.NestedChanged.Count > 0 || diff.NestedAdded.Count > 0)
        {
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Целостность", Analyzer = "Оригинал", Weight = 30, Signal = "Правка чистого мода",
                Title = $"Внутри «{proj.Value.Title}» {match.VersionNumber} подменены вложенные jar: изменено — {diff.NestedChanged.Count}, добавлено — {diff.NestedAdded.Count}",
                Why = $"Настоящий {proj.Value.Title} {match.VersionNumber} скачан с Modrinth и сравнен с файлом: вложенные модули ниже отличаются от авторских или добавлены. В них и спрятан посторонний код; каждый такой jar проверен отдельно ниже.",
            }
            .EvLines("Изменённые вложенные jar", diff.NestedChanged.Take(40))
            .EvLines("Добавленные вложенные jar", diff.NestedAdded.Take(40)));
            foreach (var n in u.Nested) if (diff.NestedChanged.Contains(n.EntryPath) || diff.NestedAdded.Contains(n.EntryPath)) n.Tampered = true;
        }

        if (diff.Added.Count > 0 || diff.Changed.Count > 0)
        {
            double w = 20 + diff.AddedClasses.Count * 2 + diff.ChangedClasses.Count;
            ctx.Add(new Finding
            {
                Severity = Severity.Critical, Category = "Целостность", Analyzer = "Оригинал", Weight = Math.Min(w, 40),
                Signal = "Правка чистого мода",
                Title = $"Файл отличается от оригинала «{proj.Value.Title}» {match.VersionNumber}: добавлено классов — {diff.AddedClasses.Count}, изменено — {diff.ChangedClasses.Count}",
                Why = $"Взят настоящий {proj.Value.Title} {match.VersionNumber} с Modrinth (sha1 {match.Sha1[..12]}…) и в него внесены изменения. Ниже — ровно те классы, которых в оригинале нет или которые переписаны. Именно в них и надо искать вредоносную логику: остальное — неизменный код автора.",
            }
            .EvLines("Добавленные классы (их не было у автора)", diff.AddedClasses.Take(60))
            .EvLines("Изменённые классы", diff.ChangedClasses.Take(60))
            .EvLines("Изменённые метаданные", diff.Notes));
        }
    }

    /// <summary>
    /// Релиз, с которым сравнивать: точное совпадение номера, иначе номер, содержащий заявленный как отдельный токен
    /// («FORGE-mc1.20.1-v1.7.3» для «1.7.3»). Из нескольких — тот, чьё имя файла совпадает или содержит версию игры из имени jar.
    /// </summary>
    private static Modrinth.VersionFile? PickCandidate(List<Modrinth.VersionFile> versions, string claimed, string fileName)
    {
        if (claimed.Length == 0 || claimed.Contains("${")) return null;
        var exact = versions.Where(v => v.VersionNumber == claimed).ToList();
        var cands = exact.Count > 0 ? exact : versions.Where(v => System.Text.RegularExpressions.Regex.IsMatch(v.VersionNumber,
            @"(^|[^0-9.])" + System.Text.RegularExpressions.Regex.Escape(claimed) + @"($|[^0-9])")).ToList();
        if (cands.Count == 0) return null;
        var byName = cands.FirstOrDefault(v => string.Equals(v.FileName, fileName, StringComparison.OrdinalIgnoreCase));
        if (byName is not null) return byName;
        var mc = System.Text.RegularExpressions.Regex.Match(fileName, @"(?:mc)?(1\.\d+(?:\.\d+)?|2\d\.\d+(?:\.\d+)?)");
        if (mc.Success)
        {
            var byGame = cands.FirstOrDefault(v => v.GameVersions.Contains(mc.Groups[1].Value));
            if (byGame is not null) return byGame;
        }
        return cands[0];
    }

    private static string VersionCore(string v)
    {
        int plus = v.IndexOf('+');
        return plus > 0 ? v[..plus] : v;
    }
}
