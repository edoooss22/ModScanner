using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ModScanner.Core;

/// <summary>
/// Клиент Modrinth: проверка хешей (найден — значит файл байт в байт совпадает с опубликованным),
/// поиск оригинала по заявленным id и версии, загрузка оригинала для сверки. Ответы кешируются на диске.
/// </summary>
internal sealed class Modrinth
{
    private const string Api = "https://api.modrinth.com/v2";
    private readonly HttpClient _http;
    private readonly string _cacheDir;
    private readonly string _hashCachePath;
    private readonly JsonObject _hashCache;
    private bool _hashCacheDirty;
    public bool Offline;
    public readonly List<string> Log = new();

    public Modrinth(string cacheDir, bool offline)
    {
        _cacheDir = cacheDir;
        Offline = offline;
        Directory.CreateDirectory(cacheDir);
        Directory.CreateDirectory(Path.Combine(cacheDir, "files"));
        _hashCachePath = Path.Combine(cacheDir, "modrinth-hashes.json");
        _hashCache = new JsonObject();
        try { if (File.Exists(_hashCachePath)) _hashCache = JsonNode.Parse(File.ReadAllText(_hashCachePath)) as JsonObject ?? new JsonObject(); } catch { }
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("ModScanner/2.0 (anticheat mod file verification)");
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public void SaveCache()
    {
        if (!_hashCacheDirty) return;
        try { File.WriteAllText(_hashCachePath, _hashCache.ToJsonString(new JsonSerializerOptions { WriteIndented = false })); } catch { }
        _hashCacheDirty = false;
    }

    /// <summary>Пакетная проверка: sha1 → результат. Отсутствие в ответе = файла в Modrinth нет.</summary>
    public Dictionary<string, ModrinthResult> LookupHashes(IEnumerable<string> sha1s)
    {
        var result = new Dictionary<string, ModrinthResult>(StringComparer.Ordinal);
        var need = new List<string>();
        foreach (var h in sha1s.Distinct())
        {
            if (_hashCache[h] is JsonObject cached && cached["t"] is JsonValue tv && tv.TryGetValue<long>(out long t)
                && DateTimeOffset.UtcNow.ToUnixTimeSeconds() - t < 7 * 86400)
            {
                result[h] = FromCache(cached);
            }
            else need.Add(h);
        }
        if (need.Count == 0) return result;
        if (Offline)
        {
            foreach (var h in need) result[h] = new ModrinthResult { Queried = false, Error = "автономный режим" };
            return result;
        }
        for (int i = 0; i < need.Count; i += 100)
        {
            var batch = need.Skip(i).Take(100).ToList();
            try
            {
                var body = new JsonObject { ["hashes"] = new JsonArray(batch.Select(h => (JsonNode)h).ToArray()), ["algorithm"] = "sha1" };
                using var resp = _http.PostAsync(Api + "/version_files", new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")).GetAwaiter().GetResult();
                string text = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                if (!resp.IsSuccessStatusCode)
                {
                    Log.Add($"version_files: HTTP {(int)resp.StatusCode}");
                    foreach (var h in batch) result[h] = new ModrinthResult { Queried = false, Error = $"HTTP {(int)resp.StatusCode}" };
                    continue;
                }
                var obj = JsonNode.Parse(text) as JsonObject ?? new JsonObject();
                var projectIds = new HashSet<string>();
                foreach (var h in batch)
                {
                    var r = new ModrinthResult { Queried = true };
                    if (obj[h] is JsonObject v)
                    {
                        r.Found = true;
                        r.ProjectId = v["project_id"]?.GetValue<string>() ?? "";
                        r.VersionId = v["id"]?.GetValue<string>() ?? "";
                        r.VersionNumber = v["version_number"]?.GetValue<string>() ?? "";
                        r.VersionName = v["name"]?.GetValue<string>() ?? "";
                        r.Status = v["status"]?.GetValue<string>() ?? "";
                        if (v["game_versions"] is JsonArray gv) foreach (var g in gv) r.GameVersions.Add(g?.GetValue<string>() ?? "");
                        if (v["files"] is JsonArray files)
                            foreach (var f in files)
                                if (f is JsonObject fo && fo["hashes"]?["sha1"]?.GetValue<string>() == h)
                                { r.FileName = fo["filename"]?.GetValue<string>() ?? ""; r.Url = fo["url"]?.GetValue<string>() ?? ""; }
                        if (r.ProjectId.Length > 0) projectIds.Add(r.ProjectId);
                    }
                    result[h] = r;
                }
                // названия проектов
                if (projectIds.Count > 0)
                {
                    var titles = ProjectTitles(projectIds);
                    foreach (var h in batch)
                        if (result[h].Found && titles.TryGetValue(result[h].ProjectId, out var ts))
                        { result[h].ProjectTitle = ts.Title; result[h].ProjectSlug = ts.Slug; }
                }
                foreach (var h in batch) if (result[h].Queried) { _hashCache[h] = ToCache(result[h]); _hashCacheDirty = true; }
            }
            catch (Exception ex)
            {
                Log.Add("version_files: " + ex.Message);
                foreach (var h in batch) result[h] = new ModrinthResult { Queried = false, Error = ex.Message };
            }
        }
        return result;
    }

    private Dictionary<string, (string Title, string Slug)> ProjectTitles(IEnumerable<string> ids)
    {
        var d = new Dictionary<string, (string, string)>();
        try
        {
            string q = Uri.EscapeDataString(new JsonArray(ids.Select(i => (JsonNode)i).ToArray()).ToJsonString());
            string text = _http.GetStringAsync($"{Api}/projects?ids={q}").GetAwaiter().GetResult();
            if (JsonNode.Parse(text) is JsonArray arr)
                foreach (var p in arr)
                    if (p is JsonObject po)
                        d[po["id"]?.GetValue<string>() ?? ""] = (po["title"]?.GetValue<string>() ?? "", po["slug"]?.GetValue<string>() ?? "");
        }
        catch (Exception ex) { Log.Add("projects: " + ex.Message); }
        return d;
    }

    /// <summary>Проект по slug (обычно совпадает с id мода в fabric.mod.json). null — нет такого.</summary>
    public (string Id, string Title, string Slug)? Project(string slug)
    {
        if (Offline || slug.Length == 0) return null;
        try
        {
            using var resp = _http.GetAsync($"{Api}/project/{Uri.EscapeDataString(slug)}").GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return null;
            var po = JsonNode.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()) as JsonObject;
            if (po is null) return null;
            return (po["id"]?.GetValue<string>() ?? "", po["title"]?.GetValue<string>() ?? "", po["slug"]?.GetValue<string>() ?? "");
        }
        catch (Exception ex) { Log.Add("project: " + ex.Message); return null; }
    }

    public sealed class VersionFile
    {
        public string VersionNumber = "", VersionId = "", FileName = "", Url = "", Sha1 = "";
        public long Size;
        public List<string> GameVersions = new();
    }

    /// <summary>Все версии проекта под Fabric с основными файлами.</summary>
    public List<VersionFile> Versions(string slug, string loader = "fabric")
    {
        var list = new List<VersionFile>();
        if (Offline) return list;
        try
        {
            string text = _http.GetStringAsync($"{Api}/project/{Uri.EscapeDataString(slug)}/version?loaders=%5B%22{Uri.EscapeDataString(loader)}%22%5D").GetAwaiter().GetResult();
            if (JsonNode.Parse(text) is JsonArray arr)
                foreach (var v in arr)
                {
                    if (v is not JsonObject vo || vo["files"] is not JsonArray files) continue;
                    JsonObject? primary = null;
                    foreach (var f in files) if (f is JsonObject fo && (primary is null || fo["primary"]?.GetValue<bool>() == true)) primary = fo;
                    if (primary is null) continue;
                    var vf = new VersionFile
                    {
                        VersionNumber = vo["version_number"]?.GetValue<string>() ?? "",
                        VersionId = vo["id"]?.GetValue<string>() ?? "",
                        FileName = primary["filename"]?.GetValue<string>() ?? "",
                        Url = primary["url"]?.GetValue<string>() ?? "",
                        Sha1 = primary["hashes"]?["sha1"]?.GetValue<string>() ?? "",
                        Size = primary["size"]?.GetValue<long>() ?? 0,
                    };
                    if (vo["game_versions"] is JsonArray gv) foreach (var g in gv) vf.GameVersions.Add(g?.GetValue<string>() ?? "");
                    list.Add(vf);
                }
        }
        catch (Exception ex) { Log.Add("versions: " + ex.Message); }
        return list;
    }

    /// <summary>Скачать файл версии (кеш по sha1). null — не удалось или хеш не сошёлся.</summary>
    public byte[]? Download(VersionFile vf)
    {
        string cached = Path.Combine(_cacheDir, "files", vf.Sha1 + ".jar");
        if (File.Exists(cached))
        {
            var b = File.ReadAllBytes(cached);
            if (Convert.ToHexString(SHA1.HashData(b)).Equals(vf.Sha1, StringComparison.OrdinalIgnoreCase)) return b;
        }
        if (Offline || vf.Url.Length == 0) return null;
        if (vf.Size > 64L * 1024 * 1024) { Log.Add($"download: {vf.FileName} больше 64 МБ, пропущен"); return null; }
        try
        {
            var bytes = _http.GetByteArrayAsync(vf.Url).GetAwaiter().GetResult();
            if (!Convert.ToHexString(SHA1.HashData(bytes)).Equals(vf.Sha1, StringComparison.OrdinalIgnoreCase)) { Log.Add($"download: sha1 {vf.FileName} не сошёлся"); return null; }
            File.WriteAllBytes(cached, bytes);
            return bytes;
        }
        catch (Exception ex) { Log.Add("download: " + ex.Message); return null; }
    }

    private static JsonObject ToCache(ModrinthResult r) => new()
    {
        ["t"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), ["found"] = r.Found, ["pid"] = r.ProjectId, ["title"] = r.ProjectTitle,
        ["slug"] = r.ProjectSlug, ["vid"] = r.VersionId, ["vnum"] = r.VersionNumber, ["vname"] = r.VersionName, ["file"] = r.FileName,
        ["url"] = r.Url, ["status"] = r.Status, ["gv"] = new JsonArray(r.GameVersions.Select(g => (JsonNode)g).ToArray()),
    };

    private static ModrinthResult FromCache(JsonObject o)
    {
        var r = new ModrinthResult
        {
            Queried = true, Found = o["found"]?.GetValue<bool>() ?? false, ProjectId = o["pid"]?.GetValue<string>() ?? "",
            ProjectTitle = o["title"]?.GetValue<string>() ?? "", ProjectSlug = o["slug"]?.GetValue<string>() ?? "",
            VersionId = o["vid"]?.GetValue<string>() ?? "", VersionNumber = o["vnum"]?.GetValue<string>() ?? "",
            VersionName = o["vname"]?.GetValue<string>() ?? "", FileName = o["file"]?.GetValue<string>() ?? "",
            Url = o["url"]?.GetValue<string>() ?? "", Status = o["status"]?.GetValue<string>() ?? "",
        };
        if (o["gv"] is JsonArray gv) foreach (var g in gv) r.GameVersions.Add(g?.GetValue<string>() ?? "");
        return r;
    }
}
