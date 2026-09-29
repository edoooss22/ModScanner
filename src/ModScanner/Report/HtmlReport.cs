using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Unicode;
using ModScanner.Analysis;

namespace ModScanner.Report;

/// <summary>
/// HTML-отчёты: сводка по всем файлам и отдельная страница на каждый мод. Страницы самодостаточны
/// (данные — JSON внутри страницы, стили и скрипт — встроены), открываются без сети.
/// </summary>
internal static class HtmlReport
{
    private static JsonSerializerOptions JsonOpts() => new() { Encoder = JavaScriptEncoder.Create(UnicodeRanges.All), WriteIndented = false };

    // целевые функции для панели «что найдено»
    private static readonly (string Group, string Signal, string Title)[] Functions =
    {
        ("Бой", "KillAura", "KillAura"),
        ("Бой", "TriggerBot", "TriggerBot"),
        ("Бой", "HitBox", "HitBox"),
        ("Бой", "Reach", "Reach"),
        ("Бой", "AimAssist", "AimAssist"),
        ("Авторизация", "Внешняя авторизация", "Внешняя авторизация"),
        ("Авторизация", "Загрузка кода из сети", "Загрузка кода с сервера"),
        ("Пакеты", "FakeLag / Blink", "FakeLag / Blink"),
        ("Пакеты", "PingSpoof", "PingSpoof"),
        ("Пакеты", "Задержка входящих пакетов", "Задержка входящих"),
        ("Вредоносное", "Скачивание и запуск файла", "Скачивание и запуск файла"),
        ("Вредоносное", "Кража данных", "Кража данных (стилер)"),
        ("Вредоносное", "Кража токена сессии", "Токен сессии в сеть"),
        ("Вредоносное", "Отправка данных на вебхук", "Отправка на вебхук"),
    };

    public static string RenderSummary(List<FileResult> results, bool offline, string detailDir)
    {
        var payload = Base("summary", offline);
        payload["files"] = new JsonArray(results.Select(r => FileCard(r, detailDir)).ToArray());
        payload["functions"] = FunctionsJson();
        return Wrap(payload, "ModScanner — сводка");
    }

    /// <summary>Машиночитаемые результаты: вердикт, функции, Modrinth и находки по каждому файлу.</summary>
    public static string RenderJson(List<FileResult> results, bool offline)
    {
        var files = new JsonArray();
        foreach (var r in results)
        {
            var findings = new JsonArray();
            foreach (var ur in r.Units)
                foreach (var f in ur.Findings.Where(x => x.Severity >= Severity.Low).OrderByDescending(x => x.Severity))
                    findings.Add(new JsonObject
                    {
                        ["jar"] = ur.Unit.Parent is null ? ur.Unit.DisplayName : ur.Unit.EntryPath,
                        ["severity"] = f.Severity.ToString(), ["category"] = f.Category, ["signal"] = f.Signal,
                        ["title"] = f.Title, ["location"] = f.Location.Replace('/', '.'),
                    });
            files.Add(new JsonObject
            {
                ["file"] = r.FileName, ["path"] = r.Path, ["sha1"] = r.Root.Sha1, ["sha256"] = r.Root.Sha256,
                ["verdict"] = r.Verdict.ToString(), ["signals"] = Arr(r.Signals),
                ["modId"] = r.Root.ModId, ["modVersion"] = r.Root.ModVersion, ["loader"] = r.Root.Loader,
                ["modrinth"] = MrInfo(r.Root, r.FileName), ["report"] = Path.GetFileName(Path.GetDirectoryName(r.ReportFile) ?? "") + "/" + Path.GetFileName(r.ReportFile),
                ["findings"] = findings,
            });
        }
        var root = new JsonObject
        {
            ["version"] = Program.Version, ["generated"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), ["offline"] = offline,
            ["files"] = files,
        };
        return root.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, WriteIndented = true });
    }

    public static string RenderFile(FileResult fr, bool offline, string summaryHref, FileResult? prev, FileResult? next, string detailDirFromDetail)
    {
        var payload = Base("file", offline);
        payload["file"] = FileDetail(fr);
        payload["summary"] = summaryHref;
        payload["prev"] = prev is null ? null : new JsonObject { ["name"] = prev.FileName, ["href"] = Path.GetFileName(prev.ReportFile) };
        payload["next"] = next is null ? null : new JsonObject { ["name"] = next.FileName, ["href"] = Path.GetFileName(next.ReportFile) };
        payload["functions"] = FunctionsJson();
        return Wrap(payload, $"ModScanner — {fr.FileName}");
    }

    private static JsonObject Base(string mode, bool offline) => new()
    {
        ["mode"] = mode,
        ["version"] = Program.Version,
        ["generated"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
        ["machine"] = Environment.MachineName,
        ["user"] = Environment.UserName,
        ["offline"] = offline,
    };

    private static JsonArray FunctionsJson() =>
        new(Functions.Select(f => (JsonNode)new JsonObject { ["group"] = f.Group, ["signal"] = f.Signal, ["title"] = f.Title }).ToArray());

    // ------------------------------------------------------------------ данные

    private static JsonArray Sev(IEnumerable<Finding> fs)
    {
        var sev = new int[5];
        foreach (var f in fs) sev[(int)f.Severity]++;
        return new JsonArray(sev.Select(x => (JsonNode)x).ToArray());
    }

    private static JsonArray Arr(IEnumerable<string> xs) => new(xs.Select(x => (JsonNode)x).ToArray());

    private static string ModrinthLine(Core.ModUnit u)
    {
        if (u.Modrinth is null || !u.Modrinth.Queried) return u.Modrinth?.Error is { Length: > 0 } e ? "не проверено: " + e : "не проверялось";
        if (u.Modrinth.Found) return $"найден: {u.Modrinth.ProjectTitle} {u.Modrinth.VersionNumber}";
        return "нет на Modrinth (хеш не найден)";
    }

    /// <summary>
    /// Настоящее имя с Modrinth: для подтверждённого по хешу — проект, версия, исходное имя файла (и признак переименования);
    /// для неподтверждённого, но выдающего себя за известный проект, — за что он себя выдаёт.
    /// </summary>
    public static JsonObject? MrInfo(Core.ModUnit u, string fileName)
    {
        var mr = u.Modrinth;
        if (mr is { Found: true })
        {
            string url = mr.ProjectSlug.Length > 0 || mr.ProjectId.Length > 0
                ? $"https://modrinth.com/project/{(mr.ProjectSlug.Length > 0 ? mr.ProjectSlug : mr.ProjectId)}" + (mr.VersionId.Length > 0 ? $"/version/{mr.VersionId}" : "") : "";
            return new JsonObject
            {
                ["kind"] = "verified", ["title"] = mr.ProjectTitle, ["version"] = mr.VersionNumber, ["file"] = mr.FileName, ["url"] = url,
                ["renamed"] = mr.FileName.Length > 0 && !string.Equals(mr.FileName, fileName, StringComparison.OrdinalIgnoreCase),
                ["games"] = string.Join(", ", mr.GameVersions.Take(6)),
            };
        }
        var d = u.Diff;
        if (d is not null && d.ProjectTitle.Length > 0)
            return new JsonObject
            {
                ["kind"] = "claims", ["title"] = d.ProjectTitle, ["version"] = d.OriginalVersion, ["file"] = d.OriginalFile,
                ["url"] = d.ProjectSlug.Length > 0 ? $"https://modrinth.com/project/{d.ProjectSlug}" : "",
                ["renamed"] = d.OriginalFile.Length > 0 && !string.Equals(d.OriginalFile, fileName, StringComparison.OrdinalIgnoreCase),
                ["missing"] = d.ClaimedVersionMissing,
            };
        return null;
    }

    private static JsonObject FileCard(FileResult r, string detailDir)
    {
        var u = r.Root;
        return new JsonObject
        {
            ["idx"] = r.Index,
            ["name"] = r.FileName,
            ["path"] = r.Path,
            ["verdict"] = r.Verdict.ToString(),
            ["signals"] = Arr(r.Signals),
            ["sev"] = Sev(r.AllFindings),
            ["units"] = r.Units.Count,
            ["verified"] = r.Units.Count(x => x.Unit.Verified),
            ["elapsed"] = Math.Round(r.Elapsed.TotalSeconds, 2),
            ["href"] = detailDir + "/" + Path.GetFileName(r.ReportFile),
            ["modid"] = u.ModId,
            ["modver"] = u.ModVersion,
            ["modname"] = u.ModName,
            ["loader"] = u.Loader,
            ["modrinth"] = ModrinthLine(u),
            ["rootVerified"] = u.Verified,
            ["top"] = TopFinding(r),
            ["mr"] = MrInfo(r.Root, r.FileName),
            ["size"] = u.Bytes.Length,
        };
    }

    private static string TopFinding(FileResult r)
    {
        // сначала целевые функции (бой, авторизация, пакеты), затем остальное
        var f = r.AllFindings.Where(x => x.Severity >= Severity.High).OrderByDescending(x => x.Severity)
                 .ThenBy(x => x.Category is "Бой" or "Авторизация" or "Пакеты" ? 0 : 1).ThenByDescending(x => x.Weight).FirstOrDefault();
        return f?.Title ?? "";
    }

    private static JsonObject FileDetail(FileResult r)
    {
        var units = new JsonArray();
        foreach (var u in r.Units) units.Add(UnitDetail(u));
        return new JsonObject
        {
            ["name"] = r.FileName,
            ["path"] = r.Path,
            ["sha1"] = r.Root.Sha1,
            ["sha256"] = r.Root.Sha256,
            ["size"] = r.Root.Bytes.Length,
            ["verdict"] = r.Verdict.ToString(),
            ["signals"] = Arr(r.Signals),
            ["sev"] = Sev(r.AllFindings),
            ["elapsed"] = Math.Round(r.Elapsed.TotalSeconds, 2),
            ["units"] = units,
            ["modrinth"] = ModrinthLine(r.Root),
            ["mr"] = MrInfo(r.Root, r.FileName),
        };
    }

    private static JsonObject UnitDetail(UnitResult ur)
    {
        var u = ur.Unit;
        var findings = new JsonArray();
        int n = 0;
        foreach (var f in ur.Findings.OrderByDescending(x => x.Severity).ThenByDescending(x => x.Weight))
        {
            n++;
            var blocks = new JsonArray();
            foreach (var ev in f.Evidence) blocks.Add(new JsonArray((JsonNode)ev.Title, (JsonNode)ev.Text));
            findings.Add(new JsonObject
            {
                ["n"] = n, ["sev"] = (int)f.Severity, ["cat"] = f.Category, ["analyzer"] = f.Analyzer,
                ["title"] = f.Title, ["why"] = f.Why, ["signal"] = f.Signal, ["loc"] = f.Location.Replace('/', '.'),
                ["weight"] = f.Weight, ["blocks"] = blocks,
            });
        }

        var meta = new JsonArray();
        void M(string k, string v) { if (v.Length > 0) meta.Add(new JsonArray((JsonNode)k, (JsonNode)v)); }
        M("Файл", u.Parent is null ? u.DisplayName : u.Chain);
        M("SHA-1", u.Sha1);
        M("SHA-256", u.Sha256);
        M("Размер", $"{u.Bytes.Length:N0} байт");
        M("Загрузчик", u.Loader.Length > 0 ? u.Loader : "нет метаданных мода (библиотека)");
        M("id мода", u.ModId);
        M("Версия", u.ModVersion);
        M("Название", u.ModName);
        if (u.Fabric is not null)
        {
            M("Среда", u.Fabric.Environment);
            if (u.Fabric.Authors.Count > 0) M("Авторы", string.Join(", ", u.Fabric.Authors));
            if (u.Fabric.Entrypoints.Count > 0) M("Точки входа", string.Join("\n", u.Fabric.Entrypoints.Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}")));
            if (u.Fabric.Description.Length > 0) M("Описание", u.Fabric.Description);
        }
        if (u.Forge is not null && u.Forge.Authors.Length > 0) M("Авторы", u.Forge.Authors);
        if (u.MixinConfigs.Count > 0) M("Конфигурации Mixin", string.Join(", ", u.MixinConfigs.Select(c => c.Path)));
        M("Классов", $"{ur.ClassCount} (mixin-классов: {ur.MixinCount}, инъекций: {ur.HookCount})");
        M("Modrinth", ModrinthLine(u));
        if (u.Modrinth?.Found == true && u.Modrinth.GameVersions.Count > 0) M("Версии игры (Modrinth)", string.Join(", ", u.Modrinth.GameVersions));

        var sections = new JsonArray();
        void Sec(string title, string text) { if (text.Length > 0) sections.Add(new JsonObject { ["title"] = title, ["text"] = text }); }
        if (ur.Hooks.Count > 0) Sec($"MIXIN-ИНЪЕКЦИИ ({ur.HookCount})", string.Join("\n", ur.Hooks));
        if (ur.Decrypted.Count > 0) Sec($"РАСШИФРОВАННЫЕ СТРОКИ ({ur.Decrypted.Count})", string.Join("\n", ur.Decrypted));
        Sec($"КЛАССЫ В АРХИВЕ ({u.Classes.Count})", string.Join("\n", u.Classes.OrderBy(c => c.Zip.Name).Take(5000).Select(c =>
            (u.Diff?.FocusClasses.Contains(c.Cf.Name) == true ? "★ " : "  ") +
            $"{c.Zip.Name}  ({c.Bytes.Length} б, sha1 {c.Sha1[..8]})" + (c.Cf.ParseError ? "  [не разобран]" : ""))));
        if (u.Nested.Count > 0) Sec($"ВЛОЖЕННЫЕ JAR ({u.Nested.Count})", string.Join("\n", u.Nested.Select(x => $"{(x.Tampered ? "★ " : "  ")}{x.EntryPath}  ({x.Bytes.Length:N0} б) — {ModrinthLine(x)}")));
        if (u.Diff is not null)
        {
            var d = u.Diff;
            var sb = new StringBuilder();
            sb.AppendLine($"Проект: {d.ProjectTitle}  ({d.ProjectSlug})");
            if (d.OriginalVersion.Length > 0) sb.AppendLine($"Версия оригинала: {d.OriginalVersion}  файл {d.OriginalFile}  sha1 {d.OriginalSha1}");
            if (d.ClaimedVersionMissing) sb.AppendLine("Заявленной версии у автора нет.");
            if (d.Error.Length > 0) sb.AppendLine("Ошибка сверки: " + d.Error);
            if (d.AddedClasses.Count > 0) { sb.AppendLine($"\nДобавлено классов ({d.AddedClasses.Count}):"); foreach (var c in d.AddedClasses) sb.AppendLine("  + " + c); }
            if (d.ChangedClasses.Count > 0) { sb.AppendLine($"\nИзменено классов ({d.ChangedClasses.Count}):"); foreach (var c in d.ChangedClasses) sb.AppendLine("  ~ " + c); }
            if (d.NestedChanged.Count > 0) { sb.AppendLine($"\nИзменены вложенные jar ({d.NestedChanged.Count}):"); foreach (var c in d.NestedChanged) sb.AppendLine("  ~ " + c); }
            if (d.NestedAdded.Count > 0) { sb.AppendLine($"\nДобавлены вложенные jar ({d.NestedAdded.Count}):"); foreach (var c in d.NestedAdded) sb.AppendLine("  + " + c); }
            if (d.Removed.Count > 0) sb.AppendLine($"\nУдалено записей: {d.Removed.Count}");
            Sec("СВЕРКА С ОРИГИНАЛОМ (MODRINTH)", sb.ToString());
        }
        if (u.LoadErrors.Count > 0) Sec("ОШИБКИ ЗАГРУЗКИ", string.Join("\n", u.LoadErrors));

        return new JsonObject
        {
            ["name"] = u.Parent is null ? u.DisplayName : u.EntryPath,
            ["chain"] = u.Chain,
            ["depth"] = u.Depth,
            ["verdict"] = ur.Verdict.ToString(),
            ["verified"] = u.Verified,
            ["tampered"] = u.Tampered,
            ["score"] = Math.Round(ur.Score, 1),
            ["signals"] = Arr(ur.Signals),
            ["sev"] = Sev(ur.Findings),
            ["meta"] = meta,
            ["findings"] = findings,
            ["sections"] = sections,
        };
    }

    // ------------------------------------------------------------------ каркас

    private static string Wrap(JsonObject payload, string title)
    {
        var sb = new StringBuilder(1 << 20);
        sb.Append(Head.Replace("__TITLE__", HtmlEscape(title)));
        sb.Append(Body);
        sb.Append("<script id=\"data\" type=\"application/json\">");
        sb.Append(payload.ToJsonString(JsonOpts()).Replace("</", "<\\/"));
        sb.Append("</script>\n<script>");
        sb.Append(Script);
        sb.Append("</script>\n</body>\n</html>\n");
        return sb.ToString();
    }

    private static string HtmlEscape(string s) => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private const string Head = """
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#0f1216; --bg2:#161a20; --bg3:#1d222a; --line:#272d37;
  --fg:#e6e9ef; --fg2:#a4adbb; --fg3:#6b7482;
  --crit:#f0454b; --high:#f59f00; --med:#22b8cf; --low:#7c8695; --info:#5f6b7a;
  --ok:#37b24d; --accent:#4c8dff; --verified:#20c997;
  --g-combat:#f0454b; --g-auth:#b36bff; --g-net:#f59f00; --g-int:#7c8695;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
}
:root[data-theme="light"]{
  --bg:#f4f6f9; --bg2:#ffffff; --bg3:#eef1f5; --line:#d7dde5;
  --fg:#12161c; --fg2:#4a5462; --fg3:#79838f;
  --crit:#d0323a; --high:#b56a00; --med:#0b7285; --low:#5c6570; --info:#6b7480; --verified:#0ca678;
  --g-combat:#d0323a; --g-auth:#8a3ffc; --g-net:#b56a00; --g-int:#5c6570;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1400px;margin:0 auto;padding:0 20px 80px}
header{border-bottom:1px solid var(--line);background:var(--bg2)}
.hd{max-width:1400px;margin:0 auto;padding:16px 20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.brand{font-size:19px;font-weight:650}.brand small{color:var(--fg3);font-weight:400;font-size:12px;margin-left:8px}
.hd-right{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--bg3);color:var(--fg2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;font-size:12.5px;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.btn:hover{color:var(--fg);border-color:var(--fg3);text-decoration:none}
.btn.pri{background:rgba(76,141,255,.14);color:var(--accent);border-color:rgba(76,141,255,.45)}
.btn.pri:hover{background:rgba(76,141,255,.24)}
.nav{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:16px 0 0}
.nav .sp{flex:1}
.verdict{padding:14px 18px;border-radius:10px;border:1px solid var(--line);display:flex;gap:13px;align-items:center;font-size:15px;margin:20px 0}
.verdict b{font-weight:650}.verdict .dot{width:11px;height:11px;border-radius:50%;flex:none}
.verdict .note{color:var(--fg2);font-size:13px;margin-top:3px}
.v-cheat{background:rgba(240,69,75,.10);border-color:rgba(240,69,75,.5)}.v-cheat .dot{background:var(--crit)}
.v-susp{background:rgba(245,159,0,.10);border-color:rgba(245,159,0,.5)}.v-susp .dot{background:var(--high)}
.v-review{background:rgba(34,184,207,.10);border-color:rgba(34,184,207,.45)}.v-review .dot{background:var(--med)}
.v-clean{background:rgba(55,178,77,.10);border-color:rgba(55,178,77,.4)}.v-clean .dot{background:var(--ok)}
.v-verified{background:rgba(32,201,151,.10);border-color:rgba(32,201,151,.45)}.v-verified .dot{background:var(--verified)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.sig{background:rgba(240,69,75,.14);color:var(--crit);border-radius:20px;padding:3px 11px;font-size:12px;font-weight:600;white-space:nowrap}
.sig.g-auth{background:rgba(179,107,255,.15);color:var(--g-auth)}
.sig.g-net{background:rgba(245,159,0,.15);color:var(--g-net)}
.sig.g-int{background:rgba(124,134,149,.18);color:var(--fg2)}
.sig.g-mal{background:rgba(240,69,75,.10);color:var(--crit);border:1px dashed rgba(240,69,75,.55)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:16px 0}
.stat{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:11px 13px;cursor:pointer;border-left-width:3px;user-select:none}
.stat:hover{border-color:var(--fg3)}.stat.off{opacity:.4}
.stat .num{font-size:22px;font-weight:650}.stat .lbl{font-size:11px;color:var(--fg2);text-transform:uppercase;letter-spacing:.5px}
.s4{border-left-color:var(--crit)}.s4 .num{color:var(--crit)}.s3{border-left-color:var(--high)}.s3 .num{color:var(--high)}
.s2{border-left-color:var(--med)}.s2 .num{color:var(--med)}.s1{border-left-color:var(--low)}.s1 .num{color:var(--low)}
.s0{border-left-color:var(--info)}.s0 .num{color:var(--info)}
.sv-verified{border-left-color:var(--verified)}.sv-verified .num{color:var(--verified)}.sv-clean{border-left-color:var(--ok)}.sv-clean .num{color:var(--ok)}
.file-row{background:var(--bg2);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:14px 16px;margin-bottom:10px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;cursor:pointer}
.file-row:hover{border-color:var(--fg3)}
.file-row .nm{font-weight:600;font-size:14.5px;word-break:break-all}
.file-row .sub{color:var(--fg3);font-size:12px;margin-top:3px}
.file-row .top{color:var(--fg2);font-size:12.5px;margin-top:5px}
.mr{font-size:12.5px;color:var(--fg2);margin-top:3px}.mr b{color:var(--verified);font-weight:600}.mr b a{color:inherit}
.mr.warn b{color:var(--high)}.mr code{font-family:var(--mono);font-size:12px;background:var(--bg3);padding:1px 5px;border-radius:4px}
.ren{font-size:10.5px;font-weight:700;letter-spacing:.4px;color:var(--high);border:1px solid rgba(245,159,0,.5);border-radius:5px;padding:1px 6px;margin-left:6px;vertical-align:2px}
.vd{font-size:12px;font-weight:700;padding:3px 9px;border-radius:6px;white-space:nowrap}
.fr-cheat{border-left-color:var(--crit)}.fr-susp{border-left-color:var(--high)}.fr-review{border-left-color:var(--med)}
.fr-clean{border-left-color:var(--ok)}.fr-verified{border-left-color:var(--verified)}
.vd-cheat{background:rgba(240,69,75,.16);color:var(--crit)}.vd-susp{background:rgba(245,159,0,.16);color:var(--high)}
.vd-review{background:rgba(34,184,207,.14);color:var(--med)}.vd-clean{background:rgba(55,178,77,.14);color:var(--ok)}
.vd-verified{background:rgba(32,201,151,.15);color:var(--verified)}
.fn-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;margin:14px 0}
.fn{background:var(--bg2);border:1px solid var(--line);border-radius:9px;padding:9px 12px;display:flex;gap:9px;align-items:center;font-size:13px}
.fn .ic{width:9px;height:9px;border-radius:50%;background:var(--line);flex:none}
.fn .gr{font-size:10.5px;color:var(--fg3);text-transform:uppercase;letter-spacing:.4px}
.fn.on{border-color:rgba(240,69,75,.55);background:rgba(240,69,75,.08)}.fn.on .ic{background:var(--crit)}
.fn.maybe{border-color:rgba(245,159,0,.5);background:rgba(245,159,0,.07)}.fn.maybe .ic{background:var(--high)}
.fn.on b{color:var(--crit)}.fn.maybe b{color:var(--high)}
.fn.off b{color:var(--fg3);font-weight:500}
.meta{background:var(--bg2);border:1px solid var(--line);border-radius:10px;margin:14px 0}
.meta summary{padding:11px 14px;cursor:pointer;font-weight:600;font-size:13.5px}
.meta .in{padding:0 14px 13px;display:grid;grid-template-columns:minmax(150px,240px) 1fr;gap:5px 16px;font-size:13px}
.meta .k{color:var(--fg2)}.meta .v{font-family:var(--mono);font-size:12.5px;word-break:break-word;white-space:pre-wrap}
.unit{border:1px solid var(--line);border-radius:11px;margin:16px 0;background:var(--bg2);overflow:hidden;border-left-width:4px}
.unit.u-cheat{border-left-color:var(--crit)}.unit.u-susp{border-left-color:var(--high)}.unit.u-review{border-left-color:var(--med)}
.unit.u-clean{border-left-color:var(--ok)}.unit.u-verified{border-left-color:var(--verified)}
.unit-hd{padding:13px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.unit-hd .nm{font-weight:600;word-break:break-all}
.unit-body{padding:6px 16px 16px}
.bar{position:sticky;top:0;z-index:20;background:var(--bg);padding:12px 0 10px;border-bottom:1px solid var(--line);margin:14px 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.search{flex:1;min-width:220px;background:var(--bg2);border:1px solid var(--line);border-radius:8px;padding:8px 11px;color:var(--fg);font-size:13.5px;font-family:inherit}
.search:focus{outline:none;border-color:var(--accent)}
.card{background:var(--bg2);border:1px solid var(--line);border-left-width:3px;border-radius:10px;margin-bottom:9px;overflow:hidden}
.card.c4{border-left-color:var(--crit)}.card.c3{border-left-color:var(--high)}.card.c2{border-left-color:var(--med)}
.card.c1{border-left-color:var(--low)}.card.c0{border-left-color:var(--info)}
.chd{display:flex;gap:11px;align-items:flex-start;padding:11px 14px;cursor:pointer}.chd:hover{background:var(--bg3)}
.badge{font-size:10.5px;font-weight:700;letter-spacing:.5px;padding:3px 7px;border-radius:5px;flex:none;margin-top:1px;white-space:nowrap}
.b4{background:rgba(240,69,75,.16);color:var(--crit)}.b3{background:rgba(245,159,0,.16);color:var(--high)}
.b2{background:rgba(34,184,207,.14);color:var(--med)}.b1{background:rgba(124,134,149,.16);color:var(--low)}.b0{background:rgba(95,107,122,.16);color:var(--info)}
.cat{font-size:11px;color:var(--fg3);border:1px solid var(--line);border-radius:5px;padding:2px 7px;flex:none;margin-top:1px}
.ttl{flex:1;font-size:13.8px;line-height:1.45;word-break:break-word}
.ttl .sg{color:var(--crit);font-weight:600}
.cbody{padding:0 14px 13px;border-top:1px solid var(--line);display:none}.card.open .cbody{display:block}
.why{color:var(--fg2);font-size:13px;line-height:1.6;margin:11px 0;padding-left:11px;border-left:2px solid var(--line)}
.loc{font-family:var(--mono);font-size:12px;color:var(--fg3);margin:6px 0;word-break:break-all}
.blk{margin:9px 0;border:1px solid var(--line);border-radius:8px;background:var(--bg3)}
.blk summary{padding:7px 11px;cursor:pointer;font-size:12.5px;color:var(--fg2)}
.blk pre{margin:0;padding:11px;overflow-x:auto;font-family:var(--mono);font-size:12px;line-height:1.45;white-space:pre;border-top:1px solid var(--line)}
.empty{color:var(--fg3);text-align:center;padding:30px 0}
.sec details{margin:9px 0;border:1px solid var(--line);border-radius:8px;background:var(--bg2)}
.sec summary{padding:9px 13px;cursor:pointer;font-weight:600;font-size:13px}
.sec pre{margin:0;padding:11px 13px;overflow:auto;max-height:60vh;font-family:var(--mono);font-size:12px;white-space:pre;border-top:1px solid var(--line)}
footer{color:var(--fg3);font-size:12px;text-align:center;padding:26px 0}
.lead{color:var(--fg2);font-size:13.5px;line-height:1.7;background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:14px 0}
h2.fname{margin:16px 0 4px;word-break:break-all;font-size:21px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.seg button{background:var(--bg2);color:var(--fg2);border:0;border-right:1px solid var(--line);padding:7px 11px;font-size:12.5px;cursor:pointer;font-family:inherit}
.seg button:last-child{border-right:0}.seg button.on{background:var(--bg3);color:var(--fg)}
@media (max-width:640px){.meta .in{grid-template-columns:1fr}.file-row{gap:10px}}
</style>
</head>
<body>
""";

    private const string Body = """
<header><div class="hd">
  <div><div class="brand">ModScanner <small id="sub"></small></div><div id="hd2" style="color:var(--fg2);font-size:12.5px;margin-top:3px"></div></div>
  <div class="hd-right" id="hdr"></div>
</div></header>
<div class="wrap"><div id="root"></div><footer id="foot"></footer></div>
""";

    private const string Script = """
const D = JSON.parse(document.getElementById('data').textContent);
const SEV=[['ИНФО','b0'],['НИЗКАЯ','b1'],['СРЕДНЯЯ','b2'],['ВЫСОКАЯ','b3'],['КРИТИЧНО','b4']];
const VD={Cheat:['ЧИТ','cheat'],Suspicious:['ПОДОЗРИТЕЛЬНО','susp'],Review:['ТРЕБУЕТ ПРОВЕРКИ','review'],Clean:['ЧИСТО','clean'],Verified:['ПОДТВЕРЖДЁН MODRINTH','verified']};
const VORDER=['Cheat','Suspicious','Review','Clean','Verified'];
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const FN=D.functions||[];
const GROUP=s=>{const f=FN.find(x=>x.signal===s);if(!f)return 'g-int';return f.group==='Бой'?'':f.group==='Авторизация'?'g-auth':f.group==='Пакеты'?'g-net':'g-mal';};
const chip=s=>`<span class="sig ${GROUP(s)}">${esc(s)}</span>`;
document.getElementById('sub').textContent = 'v'+D.version+' · '+D.generated;
document.getElementById('hd2').textContent = D.machine+'\\'+D.user+(D.offline?' · автономный режим (без Modrinth)':'');
const root = document.getElementById('root');
const hdr = document.getElementById('hdr');

// строка «что это на самом деле» по данным Modrinth
function mrLine(mr){
  if(!mr) return '';
  const t=mr.url?`<a href="${esc(mr.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(mr.title)}</a>`:esc(mr.title);
  if(mr.kind==='verified')
    return `<div class="mr">Modrinth: <b>${t}</b> ${esc(mr.version)}${mr.games?` <span style="color:var(--fg3)">(${esc(mr.games)})</span>`:''}`+
      (mr.renamed?` · имя файла на Modrinth: <code>${esc(mr.file)}</code>`:'')+`</div>`;
  return `<div class="mr warn">Выдаёт себя за <b>${t}</b> ${esc(mr.version)} — хеш не совпал с релизом${mr.missing?' (такой версии у автора нет)':mr.file?`, оригинал: <code>${esc(mr.file)}</code>`:''}</div>`;
}

function verdictBox(v, note){
  const [txt,cls]=VD[v]||VD.Clean;
  return `<div class="verdict v-${cls}"><span class="dot"></span><div><b>${txt}</b><div class="note">${note}</div></div></div>`;
}
function themeBtn(){ return `<button class="btn" id="bt">Тема</button>`; }

if(D.mode==='summary') renderSummary(); else renderFile();

document.getElementById('bt').onclick=()=>{const r=document.documentElement;r.dataset.theme=r.dataset.theme==='light'?'':'light';try{localStorage.setItem('ms-theme',r.dataset.theme)}catch(e){}};
try{const t=localStorage.getItem('ms-theme');if(t)document.documentElement.dataset.theme=t;}catch(e){}

// ------------------------------------------------------------------ сводка
function renderSummary(){
  hdr.innerHTML=themeBtn();
  const files=D.files;
  const cnt={}; VORDER.forEach(v=>cnt[v]=files.filter(f=>f.verdict===v).length);
  const worst = VORDER.find(v=>cnt[v]>0 && v!=='Verified' && v!=='Clean') || (cnt.Clean?'Clean':'Verified');
  const note = cnt.Cheat? `Читов: ${cnt.Cheat}, подозрительных: ${cnt.Suspicious}. Нажмите на мод — подробный отчёт откроется отдельно.`
    : cnt.Suspicious? `Подозрительных модов: ${cnt.Suspicious}. Критических признаков нет, но есть что проверить.`
    : cnt.Review? `Явных читов нет, ${cnt.Review} мод(ов) требуют ручной проверки.` : 'Читерских функций не найдено.';
  let h = verdictBox(worst, note);
  h += `<div class="lead">Проверено файлов: <b>${files.length}</b>. Каждый jar (и вложенные) сверен с Modrinth по SHA-1 и разобран полностью: байт-код, Mixin-инъекции, строки. Ищутся боевые функции (<b>KillAura, TriggerBot, HitBox, Reach, AimAssist</b>), <b>внешняя авторизация</b> и загрузка кода с сервера, <b>манипуляция пакетами</b> для ухудшения пинга (FakeLag/Blink, PingSpoof, задержка входящих). Подтверждение Modrinth означает подлинность файла, а не отсутствие читов — функции ищутся и в подтверждённых модах.</div>`;
  h += '<div class="stats" id="vstats">';
  const vs=[['Cheat','s4'],['Suspicious','s3'],['Review','s2'],['Clean','sv-clean'],['Verified','sv-verified']];
  vs.forEach(([v,c])=>h+=`<div class="stat ${c}" data-v="${v}"><div class="num">${cnt[v]}</div><div class="lbl">${VD[v][0]}</div></div>`);
  h += '</div>';
  h +=`<div class="bar"><input class="search" id="q" placeholder="Фильтр: имя файла, id мода, функция…"><span id="fl" style="color:var(--fg3);font-size:12.5px"></span></div>`;
  h += '<div id="files"></div>';
  root.innerHTML=h;
  const box=document.getElementById('files');
  const order=f=>VORDER.indexOf(f.verdict);
  [...files].sort((a,b)=>order(a)-order(b)||a.name.localeCompare(b.name)).forEach(f=>{
    const [txt,cls]=VD[f.verdict]||VD.Clean;
    const cntF=f.sev.reduce((a,b)=>a+b,0);
    const id=[f.modname||f.modid, f.modver].filter(Boolean).join(' ');
    const idx=(f.name+' '+f.modid+' '+f.modname+' '+f.signals.join(' ')+' '+txt+' '+(f.mr?f.mr.title+' '+f.mr.file:'')).toLowerCase();
    box.insertAdjacentHTML('beforeend',
      `<div class="file-row fr-${cls}" data-v="${f.verdict}" data-idx="${esc(idx)}" data-sigs="${esc(f.signals.join('|'))}" data-href="${esc(f.href)}">`+
      `<div style="flex:1;min-width:240px"><div class="nm">${esc(f.name)}${f.mr&&f.mr.renamed?' <span class="ren">ПЕРЕИМЕНОВАН</span>':''}</div>`+
      mrLine(f.mr)+
      `<div class="sub">${esc(id)}${f.loader?' · '+esc(f.loader):''}${f.mr?'':' · Modrinth: '+esc(f.modrinth)} · jar: ${f.units} · находок: ${cntF} · ${f.elapsed}s</div>`+
      (f.top?`<div class="top">${esc(f.top)}</div>`:'')+`</div>`+
      `<div class="chips">${f.signals.map(chip).join('')}</div><div class="vd vd-${cls}">${txt}</div>`+
      `<a class="btn pri" href="${esc(f.href)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Открыть отчёт ↗</a></div>`);
  });
  box.querySelectorAll('.file-row').forEach(r=>r.onclick=()=>window.open(r.dataset.href,'_blank'));
  const off=new Set();
  const apply=()=>{const t=(document.getElementById('q').value||'').toLowerCase().trim();let n=0;
    box.querySelectorAll('.file-row').forEach(r=>{const ok=!off.has(r.dataset.v)&&(!t||r.dataset.idx.includes(t));r.style.display=ok?'':'none';if(ok)n++;});
    document.getElementById('fl').textContent=`показано ${n} из ${files.length}`;};
  document.querySelectorAll('#vstats .stat').forEach(s=>s.onclick=()=>{const v=s.dataset.v;off.has(v)?off.delete(v):off.add(v);s.classList.toggle('off');apply();});
  document.getElementById('q').oninput=apply; apply();
  document.getElementById('foot').textContent='ModScanner '+D.version+' · файлов: '+files.length;
}

// ------------------------------------------------------------------ отчёт по моду
function renderFile(){
  const f=D.file;
  hdr.innerHTML=`<button class="btn" id="be">Развернуть всё</button><button class="btn" id="bc">Свернуть всё</button>`+themeBtn();
  const note = f.verdict==='Cheat'?'Найдены читерские функции или подмена кода. Разбор — в находках ниже.'
    : f.verdict==='Suspicious'?'Есть сильные признаки, требующие объяснения.'
    : f.verdict==='Review'?'Есть что проверить вручную.'
    : f.verdict==='Verified'?'Файл побайтно совпал с релизом на Modrinth, читерских функций не найдено.'
    : 'Читерских функций и посторонней логики не найдено.';
  let h=`<div class="nav"><a class="btn" href="${esc(D.summary)}">← Сводка</a>`+
    (D.prev?`<a class="btn" href="${esc(D.prev.href)}" title="${esc(D.prev.name)}">‹ Предыдущий</a>`:'')+
    (D.next?`<a class="btn" href="${esc(D.next.href)}" title="${esc(D.next.name)}">Следующий ›</a>`:'')+`</div>`;
  h += `<h2 class="fname">${esc(f.name)}${f.mr&&f.mr.renamed?' <span class="ren">ПЕРЕИМЕНОВАН</span>':''}</h2>`;
  h += mrLine(f.mr);
  h += `<div class="loc">${esc(f.path)}<br>SHA-1 ${f.sha1} · ${f.size.toLocaleString('ru')} байт · Modrinth: ${esc(f.modrinth)} · ${f.elapsed}s</div>`;
  h += verdictBox(f.verdict, note);
  // панель функций
  const all=f.units.flatMap(u=>u.findings);
  h+='<div class="fn-grid">';
  FN.forEach(fn=>{
    const hits=all.filter(x=>x.signal===fn.signal);
    const top=hits.reduce((a,b)=>Math.max(a,b.sev),-1);
    const cls=top>=4?'on':top>=2?'maybe':'off';
    const lbl=top>=4?'найдено':top>=2?'признаки':'не найдено';
    h+=`<div class="fn ${cls}"><span class="ic"></span><div><div class="gr">${esc(fn.group)}</div><b>${esc(fn.title)}</b> <span style="color:var(--fg3);font-size:12px">— ${lbl}</span></div></div>`;
  });
  h+='</div>';
  h += '<div class="stats" id="sstats">';
  for(let s=4;s>=0;s--) h+=`<div class="stat s${s}" data-sev="${s}"><div class="num">${f.sev[s]}</div><div class="lbl">${SEV[s][0]}</div></div>`;
  h += '</div>';
  h += `<div class="bar"><input class="search" id="q" placeholder="Поиск по находкам: класс, API, приём…  ( / )"></div>`;
  h += '<div id="units"></div>';
  root.innerHTML=h;
  const box=document.getElementById('units');
  const flagged=f.units.filter(u=>u.findings.length>0);
  const clean=f.units.filter(u=>u.findings.length===0);
  flagged.forEach(u=>box.insertAdjacentHTML('beforeend', unitHtml(u)));
  if(clean.length){
    const rows=clean.map(u=>{const [t,c]=VD[u.verdict]||VD.Clean;return `<div style="display:flex;gap:10px;padding:6px 4px;border-bottom:1px solid var(--line);font-size:12.5px;align-items:center"><span class="vd vd-${c}" style="font-size:10.5px">${t}</span><span style="color:var(--fg2);word-break:break-all">${esc(u.depth>0?'↳ '+u.name:u.name)}</span></div>`;}).join('');
    box.insertAdjacentHTML('beforeend',`<details class="meta"><summary>Без находок: ${clean.length} jar (подтверждены Modrinth: ${clean.filter(u=>u.verified).length})</summary><div style="padding:0 14px 12px">${rows}</div></details>`);
    // полные данные корня, если у него нет находок
    const r=clean.find(u=>u.depth===0); if(r) box.insertAdjacentHTML('beforeend', unitHtml(r));
  }
  if(flagged.length===0) box.insertAdjacentHTML('afterbegin','<div class="lead">Ни в самом jar, ни во вложенных находок нет.</div>');
  wire();
  document.getElementById('foot').textContent='ModScanner '+D.version+' · '+f.name;
}

function unitHtml(u){
  const [txt,cls]=VD[u.verdict]||VD.Clean;
  let h=`<div class="unit u-${cls}"><div class="unit-hd"><div class="nm">${u.depth>0?'↳ вложенный: ':''}${esc(u.name)}</div>`+
    `<div class="vd vd-${cls}">${txt}</div>${u.tampered?'<div class="vd vd-cheat">ИЗМЕНЁН ОТНОСИТЕЛЬНО ОРИГИНАЛА</div>':''}<div class="chips">${u.signals.map(chip).join('')}</div>`+
    `<div style="color:var(--fg3);font-size:12px;margin-left:auto">балл ${u.score}</div></div><div class="unit-body">`;
  h+=`<details class="meta"><summary>Сведения о jar</summary><div class="in">`;
  u.meta.forEach(([k,v])=>h+=`<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`);
  h+=`</div></details>`;
  if(u.findings.length===0) h+=`<div class="empty">Находок нет.</div>`;
  else u.findings.forEach(fd=>h+=cardHtml(fd));
  if(u.sections && u.sections.length){
    h+='<div class="sec">';
    u.sections.forEach(s=>h+=`<details><summary>${esc(s.title)}</summary><pre>${esc(s.text)}</pre></details>`);
    h+='</div>';
  }
  return h+'</div></div>';
}

function cardHtml(fd){
  const [nm,bc]=SEV[fd.sev];
  const sg=fd.signal&&fd.sev>=3?`<span class="sg">[${esc(fd.signal)}] </span>`:'';
  let blocks='';
  fd.blocks.forEach(([t,txt])=>{ if(txt&&txt.length) blocks+=`<details class="blk" ${fd.sev>=3?'open':''}><summary>${esc(t)}</summary><pre>${esc(txt)}</pre></details>`; });
  const idx=(fd.title+' '+fd.why+' '+fd.cat+' '+(fd.signal||'')+' '+fd.loc+' '+fd.blocks.map(b=>b[1]).join(' ')).toLowerCase();
  return `<div class="card c${fd.sev}${fd.sev>=4?' open':''}" data-sev="${fd.sev}" data-idx="${esc(idx)}">`+
    `<div class="chd"><span class="badge ${bc}">${nm}</span><span class="cat">${esc(fd.cat)}</span>`+
    `<span class="ttl">${sg}${esc(fd.title)}</span></div>`+
    `<div class="cbody"><div class="why">${esc(fd.why)}</div>`+
    (fd.loc?`<div class="loc">${esc(fd.loc)}</div>`:'')+blocks+`</div></div>`;
}

function wire(){
  document.querySelectorAll('.chd').forEach(c=>c.onclick=()=>c.parentElement.classList.toggle('open'));
  const off=new Set();
  const q=document.getElementById('q');
  const apply=()=>{const t=(q.value||'').toLowerCase().trim();
    document.querySelectorAll('.card').forEach(c=>{c.style.display=(!t||c.dataset.idx.includes(t))&&!off.has(c.dataset.sev)?'':'none';});};
  q.oninput=apply;
  document.querySelectorAll('#sstats .stat').forEach(s=>s.onclick=()=>{const v=s.dataset.sev;off.has(v)?off.delete(v):off.add(v);s.classList.toggle('off');apply();});
  document.getElementById('be').onclick=()=>document.querySelectorAll('.card').forEach(c=>c.classList.add('open'));
  document.getElementById('bc').onclick=()=>document.querySelectorAll('.card').forEach(c=>c.classList.remove('open'));
  document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement!==q){e.preventDefault();q.focus();}});
}
""";
}
