using System.Text.Json;
using System.Text.Json.Nodes;

namespace ModScanner.Core;

internal sealed class FabricMod
{
    public string Id = "";
    public string Version = "";
    public string Name = "";
    public string Environment = "*";
    public string Description = "";
    public List<string> Authors = new();
    public Dictionary<string, List<string>> Entrypoints = new();    // ключ → классы (точечная форма)
    public List<string> MixinConfigs = new();
    public List<string> NestedJars = new();
    public Dictionary<string, string> Depends = new();
    public string? AccessWidener;
    public List<string> Provides = new();
    public bool HasCustom;
    public bool LoomGenerated;               // custom["fabric-loom:generated"] — обёртка Loom для java-библиотеки
    public bool HadBom;
    public bool ParseError;
    public string RawText = "";
    public JsonNode? Root;

    public IEnumerable<string> AllEntrypointClasses => Entrypoints.Values.SelectMany(v => v);

    public static FabricMod? Parse(byte[] data)
    {
        var m = new FabricMod();
        int off = 0;
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) { m.HadBom = true; off = 3; }
        try
        {
            m.RawText = System.Text.Encoding.UTF8.GetString(data, off, data.Length - off);
            var root = JsonNode.Parse(m.RawText, null, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (root is not JsonObject o) { m.ParseError = true; return m; }
            m.Root = root;
            m.Id = Str(o["id"]); m.Version = Str(o["version"]); m.Name = Str(o["name"]); m.Description = Str(o["description"]);
            m.Environment = o["environment"] is null ? "*" : Str(o["environment"]);
            if (o["authors"] is JsonArray aa) foreach (var a in aa) m.Authors.Add(a is JsonObject ao ? Str(ao["name"]) : Str(a));
            if (o["provides"] is JsonArray pa) foreach (var a in pa) m.Provides.Add(Str(a));
            if (o["entrypoints"] is JsonObject eo)
                foreach (var kv in eo)
                {
                    var list = new List<string>();
                    if (kv.Value is JsonArray ea)
                        foreach (var e in ea) list.Add(e is JsonObject eob ? Str(eob["value"]) : Str(e));
                    else if (kv.Value is not null) list.Add(Str(kv.Value));
                    m.Entrypoints[kv.Key] = list;
                }
            if (o["mixins"] is JsonArray ma)
                foreach (var x in ma) m.MixinConfigs.Add(x is JsonObject xo ? Str(xo["config"]) : Str(x));
            else if (o["mixins"] is JsonValue mv) m.MixinConfigs.Add(Str(mv));
            if (o["jars"] is JsonArray ja)
                foreach (var j in ja) if (j is JsonObject jo) m.NestedJars.Add(Str(jo["file"]));
            if (o["depends"] is JsonObject dob)
                foreach (var kv in dob) m.Depends[kv.Key] = kv.Value is JsonArray va ? string.Join(" || ", va.Select(Str)) : Str(kv.Value);
            if (o["accessWidener"] is not null) m.AccessWidener = Str(o["accessWidener"]);
            m.HasCustom = o["custom"] is not null;
            m.LoomGenerated = o["custom"] is JsonObject co && co["fabric-loom:generated"] is JsonValue lg && lg.TryGetValue<bool>(out var lgb) && lgb;
        }
        catch { m.ParseError = true; }
        return m;
    }

    private static string Str(JsonNode? n) => n is null ? "" : n is JsonValue v ? (v.TryGetValue<string>(out var s) ? s : v.ToJsonString()) : n.ToJsonString();
}

internal sealed class MixinConfig
{
    public string Path = "";
    public string Package = "";
    public List<string> Mixins = new();
    public List<string> Client = new();
    public List<string> Server = new();
    public string? Refmap;
    public string? Plugin;
    public bool Required;
    public string? MinVersion;
    public string? CompatibilityLevel;
    public bool ParseError;
    public bool HadBom;

    public IEnumerable<string> AllMixinClasses => Mixins.Concat(Client).Concat(Server).Select(m => Package.Replace('.', '/') + "/" + m.Replace('.', '/'));

    public static MixinConfig Parse(string path, byte[] data)
    {
        var c = new MixinConfig { Path = path };
        int off = 0;
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) { c.HadBom = true; off = 3; }
        try
        {
            var root = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data, off, data.Length - off), null,
                new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }) as JsonObject;
            if (root is null) { c.ParseError = true; return c; }
            c.Package = root["package"]?.GetValue<string>() ?? "";
            foreach (var (k, l) in new[] { ("mixins", c.Mixins), ("client", c.Client), ("server", c.Server) })
                if (root[k] is JsonArray a) foreach (var x in a) if (x is JsonValue v && v.TryGetValue<string>(out var s)) l.Add(s);
            c.Refmap = root["refmap"]?.GetValue<string>();
            c.Plugin = root["plugin"]?.GetValue<string>();
            c.Required = root["required"] is JsonValue rv && rv.TryGetValue<bool>(out var b) && b;
            c.MinVersion = root["minVersion"]?.GetValue<string>();
            c.CompatibilityLevel = root["compatibilityLevel"]?.GetValue<string>();
        }
        catch { c.ParseError = true; }
        return c;
    }
}

/// <summary>refmap: класс Mixin → (строка в аннотации в читаемых именах → строка в промежуточных).</summary>
internal sealed class Refmap
{
    public Dictionary<string, Dictionary<string, string>> ByClass = new(StringComparer.Ordinal);
    public bool ParseError;

    public static Refmap Parse(byte[] data)
    {
        var r = new Refmap();
        try
        {
            int off = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
            var root = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(data, off, data.Length - off)) as JsonObject;
            if (root?["mappings"] is JsonObject m)
                foreach (var kv in m)
                {
                    var d = new Dictionary<string, string>(StringComparer.Ordinal);
                    if (kv.Value is JsonObject o) foreach (var e in o) d[e.Key] = e.Value?.GetValue<string>() ?? "";
                    r.ByClass[kv.Key] = d;
                }
        }
        catch { r.ParseError = true; }
        return r;
    }

    public string? Map(string mixinClass, string key)
    {
        if (ByClass.TryGetValue(mixinClass, out var d) && d.TryGetValue(key, out var v)) return v;
        return null;
    }
}

/// <summary>META-INF/neoforge.mods.toml / mods.toml (NeoForge, Forge): только то, что нужно для отчёта и Modrinth.</summary>
internal sealed class ModsToml
{
    public string Loader = "";            // neoforge | forge
    public string ModId = "", Version = "", DisplayName = "", Authors = "", Description = "";
    public List<string> MixinConfigs = new();

    public static ModsToml Parse(byte[] data, string loader)
    {
        var t = new ModsToml { Loader = loader };
        string text = System.Text.Encoding.UTF8.GetString(data);
        string section = "";
        foreach (var raw in text.Split('\n'))
        {
            string line = raw.Trim();
            if (line.StartsWith("[")) { section = line.Trim('[', ']', ' '); continue; }
            int eq = line.IndexOf('=');
            if (eq <= 0 || line.StartsWith("#")) continue;
            string k = line[..eq].Trim(), v = line[(eq + 1)..].Trim();
            int hash = v.IndexOf(" #", StringComparison.Ordinal);
            if (hash > 0 && v.StartsWith('"') && v.IndexOf('"', 1) < hash) v = v[..hash].Trim();
            v = v.Trim('"', '\'');
            if (section == "mods")
            {
                if (k == "modId" && t.ModId.Length == 0) t.ModId = v;
                else if (k == "version" && t.Version.Length == 0) t.Version = v;
                else if (k == "displayName" && t.DisplayName.Length == 0) t.DisplayName = v;
                else if (k == "authors" && t.Authors.Length == 0) t.Authors = v;
                else if (k == "description" && t.Description.Length == 0) t.Description = v;
            }
            else if (section == "mixins" && k == "config") t.MixinConfigs.Add(v);
        }
        return t;
    }
}

internal static class Manifest
{
    /// <summary>Главная секция и подписи записей (Name → SHA-256-Digest).</summary>
    public static (Dictionary<string, string> Main, Dictionary<string, string> Digests) Parse(byte[] data)
    {
        var main = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var dig = new Dictionary<string, string>(StringComparer.Ordinal);
        string text = System.Text.Encoding.UTF8.GetString(data).Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n ", "");
        string? curName = null;
        bool inMain = true;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw;
            if (line.Length == 0) { inMain = false; curName = null; continue; }
            int c = line.IndexOf(':');
            if (c <= 0) continue;
            string k = line[..c].Trim(), v = line[(c + 1)..].Trim();
            if (inMain) main[k] = v;
            else if (k.Equals("Name", StringComparison.OrdinalIgnoreCase)) curName = v;
            else if (curName is not null && k.EndsWith("-Digest", StringComparison.OrdinalIgnoreCase)) dig[curName] = k.Split('-')[0] + ":" + v;
        }
        return (main, dig);
    }
}
