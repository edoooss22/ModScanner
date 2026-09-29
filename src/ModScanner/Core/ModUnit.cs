using System.Security.Cryptography;

namespace ModScanner.Core;

/// <summary>Один разобранный класс внутри jar.</summary>
internal sealed class ClassEntry
{
    public ZipEntry Zip = null!;
    public ClassFile Cf = null!;
    public byte[] Bytes = Array.Empty<byte>();
    public string Sha1 = "";
    public bool NameMismatch;          // имя в файле не совпадает с путём в архиве
    public bool HiddenExtension;       // класс лежит под чужим расширением
    public bool MultiRelease;          // META-INF/versions/N/…
    public string Name => Cf.Name.Length > 0 ? Cf.Name : Zip.Name.Replace(".class", "");
}

/// <summary>Jar как единица проверки: сам мод либо вложенный jar. Дерево вложенности сохраняется.</summary>
internal sealed class ModUnit
{
    public string Path = "";                 // путь на диске (для вложенного — путь родителя)
    public string EntryPath = "";            // для вложенного: путь внутри родителя
    public string DisplayName = "";
    public ModUnit? Parent;
    public List<ModUnit> Nested = new();
    public byte[] Bytes = Array.Empty<byte>();
    public ZipReader Zip = null!;
    public string Sha1 = "", Sha512 = "", Sha256 = "";
    public List<ClassEntry> Classes = new();
    public Dictionary<string, ClassEntry> ByName = new(StringComparer.Ordinal);
    public FabricMod? Fabric;
    public bool HasFabricJson;
    public ModsToml? Forge;                  // NeoForge / Forge
    public bool HasQuiltJson;
    /// <summary>Загрузчик по метаданным: fabric, quilt, neoforge, forge либо пусто (библиотека).</summary>
    public string Loader => Fabric is not null ? "fabric" : HasQuiltJson ? "quilt" : Forge?.Loader ?? "";
    /// <summary>Вложенная библиотека: нет метаданных мода либо fabric.mod.json сгенерирован Loom для обычной java-библиотеки.</summary>
    public bool IsLibrary => Parent is not null && (Loader.Length == 0 || Fabric?.LoomGenerated == true);
    public string ModId => Fabric?.Id is { Length: > 0 } f ? f : Forge?.ModId ?? "";
    public string ModVersion => Fabric?.Version is { Length: > 0 } f ? f : Forge?.Version ?? ManifestMain.GetValueOrDefault("Implementation-Version") ?? "";
    public string ModName => Fabric?.Name is { Length: > 0 } f ? f : Forge?.DisplayName ?? "";
    public List<MixinConfig> MixinConfigs = new();
    public Dictionary<string, Refmap> Refmaps = new(StringComparer.Ordinal);
    public Dictionary<string, string> ManifestMain = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> ManifestDigests = new(StringComparer.Ordinal);
    public bool HasManifest;
    public List<string> LoadErrors = new();
    public int Depth => Parent is null ? 0 : Parent.Depth + 1;
    public string Chain => Parent is null ? DisplayName : Parent.Chain + " › " + EntryPath;
    public ModUnit Root => Parent is null ? this : Parent.Root;

    // результаты
    public ModrinthResult? Modrinth;
    public bool Verified => Modrinth?.Found == true;
    public bool DeepScanned;
    public OriginDiff? Diff;
    public bool Tampered;                    // вложенный jar отличается от оригинала родителя

    public IEnumerable<ModUnit> SelfAndNested()
    {
        yield return this;
        foreach (var n in Nested) foreach (var x in n.SelfAndNested()) yield return x;
    }

    public static ModUnit Load(string path, byte[] bytes, ModUnit? parent = null, string entryPath = "")
    {
        var u = new ModUnit
        {
            Path = path, Bytes = bytes, Parent = parent, EntryPath = entryPath,
            DisplayName = parent is null ? System.IO.Path.GetFileName(path) : entryPath[(entryPath.LastIndexOf('/') + 1)..],
        };
        u.Sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
        u.Sha512 = Convert.ToHexString(SHA512.HashData(bytes)).ToLowerInvariant();
        u.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        try { u.Zip = new ZipReader(bytes); }
        catch (Exception ex) { u.Zip = new ZipReader(Array.Empty<byte>()); u.LoadErrors.Add("Архив не разобран: " + ex.Message); return u; }

        foreach (var e in u.Zip.Entries)
        {
            if (e.IsDirectory) continue;
            bool isClassName = e.Name.EndsWith(".class", StringComparison.Ordinal);
            byte[]? data = null;
            bool magic = false;
            // класс определяем по магическому числу, а не по расширению — так находим спрятанные классы
            if (isClassName || e.UncompressedSize >= 24)
            {
                data = u.Zip.Read(e);
                magic = data is not null && data.Length >= 4 && data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE;
            }
            if (!isClassName && !magic) continue;
            if (data is null) { u.LoadErrors.Add($"Не прочитана запись {e.Name} (метод сжатия {e.Method}, шифрование: {e.Encrypted})"); continue; }
            var cf = ClassFile.Parse(data);
            var ce = new ClassEntry
            {
                Zip = e, Cf = cf, Bytes = data, Sha1 = Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant(),
                HiddenExtension = !isClassName && magic,
                MultiRelease = e.Name.StartsWith("META-INF/versions/", StringComparison.Ordinal),
            };
            string expected = e.Name;
            if (ce.MultiRelease) { int k = expected.IndexOf('/', "META-INF/versions/".Length); if (k > 0) expected = expected[(k + 1)..]; }
            if (expected.EndsWith(".class")) expected = expected[..^6];
            ce.NameMismatch = !cf.ParseError && cf.Name != expected;
            u.Classes.Add(ce);
            if (!cf.ParseError && !ce.MultiRelease && !u.ByName.ContainsKey(cf.Name)) u.ByName[cf.Name] = ce;
        }

        var fj = u.Zip.Read("fabric.mod.json");
        if (fj is not null) { u.HasFabricJson = true; u.Fabric = FabricMod.Parse(fj); }

        if (u.Zip.Find("quilt.mod.json") is not null) u.HasQuiltJson = true;
        foreach (var (tomlPath, loader) in new[] { ("META-INF/neoforge.mods.toml", "neoforge"), ("META-INF/mods.toml", "forge") })
        {
            var td = u.Zip.Read(tomlPath);
            if (td is not null) { u.Forge = ModsToml.Parse(td, loader); break; }
        }

        var mf = u.Zip.Read("META-INF/MANIFEST.MF");
        if (mf is not null) { u.HasManifest = true; (u.ManifestMain, u.ManifestDigests) = Manifest.Parse(mf); }

        // конфигурации Mixin: заявленные в fabric.mod.json плюс все *.mixins.json в корне
        var cfgNames = new HashSet<string>(StringComparer.Ordinal);
        if (u.Fabric is not null) foreach (var c in u.Fabric.MixinConfigs) if (c.Length > 0) cfgNames.Add(c);
        if (u.Forge is not null) foreach (var c in u.Forge.MixinConfigs) if (c.Length > 0) cfgNames.Add(c);
        if (u.ManifestMain.TryGetValue("MixinConfigs", out var mcs)) foreach (var c in mcs.Split(',')) if (c.Trim().Length > 0) cfgNames.Add(c.Trim());
        foreach (var e in u.Zip.Entries)
            if (!e.IsDirectory && !e.Name.Contains('/') && e.Name.EndsWith(".json") && e.Name.Contains("mixin", StringComparison.OrdinalIgnoreCase) && !e.Name.Contains("refmap", StringComparison.OrdinalIgnoreCase))
                cfgNames.Add(e.Name);
        foreach (var n in cfgNames)
        {
            var d = u.Zip.Read(n);
            if (d is null) continue;
            var mc = MixinConfig.Parse(n, d);
            u.MixinConfigs.Add(mc);
            if (mc.Refmap is not null && !u.Refmaps.ContainsKey(mc.Refmap))
            {
                var rd = u.Zip.Read(mc.Refmap);
                if (rd is not null) u.Refmaps[mc.Refmap] = Refmap.Parse(rd);
            }
        }

        // вложенные jar: заявленные в fabric.mod.json и все *.jar в META-INF/jars
        var nested = new HashSet<string>(StringComparer.Ordinal);
        if (u.Fabric is not null) foreach (var j in u.Fabric.NestedJars) if (j.Length > 0) nested.Add(j);
        foreach (var e in u.Zip.Entries)
            if (!e.IsDirectory && e.Name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) nested.Add(e.Name);
        foreach (var n in nested.OrderBy(x => x, StringComparer.Ordinal))
        {
            var d = u.Zip.Read(n);
            if (d is null) { u.LoadErrors.Add($"Вложенный jar {n} не прочитан"); continue; }
            if (u.Depth >= 4) { u.LoadErrors.Add($"Вложенный jar {n}: глубина вложенности больше 4, пропущен"); continue; }
            u.Nested.Add(Load(path, d, u, n));
        }
        return u;
    }

    /// <summary>Класс из карты по внутреннему имени с учётом вложенных jar того же дерева не нужен: Fabric грузит их как отдельные моды.</summary>
    public ClassEntry? Find(string internalName) => ByName.TryGetValue(internalName, out var c) ? c : null;
}

internal sealed class ModrinthResult
{
    public bool Queried;
    public bool Found;
    public string ProjectId = "";
    public string ProjectTitle = "";
    public string ProjectSlug = "";
    public string VersionId = "";
    public string VersionNumber = "";
    public string VersionName = "";
    public string FileName = "";
    public string Url = "";
    public string Error = "";
    public string Status = "";
    public List<string> GameVersions = new();
}

/// <summary>Сверка с оригиналом того же мода той же версии с Modrinth.</summary>
internal sealed class OriginDiff
{
    public string OriginalFile = "";
    public string OriginalSha1 = "";
    public string OriginalVersion = "";
    public string ProjectTitle = "";
    public string ProjectSlug = "";
    public bool ClaimedVersionMissing;
    public bool OriginalDownloaded;
    public string Error = "";
    public List<string> Added = new();
    public List<string> Removed = new();
    public List<string> Changed = new();
    public List<string> AddedClasses = new();
    public List<string> NestedChanged = new();
    public List<string> NestedAdded = new();
    public List<string> ChangedClasses = new();
    public List<string> Notes = new();
    public HashSet<string> FocusClasses = new(StringComparer.Ordinal);
    public int OriginalEntries;
}
