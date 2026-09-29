using System.Text;
using ModScanner.Report;

namespace ModScanner.Analysis;

/// <summary>
/// Названия модулей чита: имена классов (KillAura, TriggerbotModule, HitBoxModule…) и строковые
/// константы, совпадающие с названием функции («kill-aura», «Trigger Bot», «FakeLag»). Это вспомогательная
/// улика: без подтверждения поведением она не даёт вердикт «чит», но указывает, где искать, и
/// выдаёт клиент, у которого поведенческие проверки ослеплены обфускацией.
/// </summary>
internal sealed class SignatureAnalyzer : IAnalyzer
{
    public string Name => "Названия";

    private sealed record Sig(string Signal, bool Strong);

    private static readonly Dictionary<string, Sig> Names = new(StringComparer.Ordinal)
    {
        ["killaura"] = new("KillAura", true), ["multiaura"] = new("KillAura", true), ["forcefield"] = new("KillAura", true),
        ["aura"] = new("KillAura", false), ["attackaura"] = new("KillAura", true), ["neuroaura"] = new("KillAura", true),
        ["triggerbot"] = new("TriggerBot", true), ["autotrigger"] = new("TriggerBot", true),
        ["hitbox"] = new("HitBox", false), ["hitboxes"] = new("HitBox", false), ["expandhitbox"] = new("HitBox", true),
        ["hitboxexpand"] = new("HitBox", true), ["hitboxexpander"] = new("HitBox", true), ["extendedhitbox"] = new("HitBox", true), ["bighitbox"] = new("HitBox", true),
        ["aimassist"] = new("AimAssist", true), ["aimbot"] = new("AimAssist", true), ["aimlock"] = new("AimAssist", true), ["bowaimbot"] = new("AimAssist", true),
        ["autoaim"] = new("AimAssist", true), ["silentaim"] = new("AimAssist", true),
        ["reach"] = new("Reach", false), ["longreach"] = new("Reach", true), ["attackreach"] = new("Reach", true), ["combatreach"] = new("Reach", true),
        ["fakelag"] = new("FakeLag / Blink", true), ["lagswitch"] = new("FakeLag / Blink", true), ["blink"] = new("FakeLag / Blink", false),
        ["fakeping"] = new("PingSpoof", true), ["pingspoof"] = new("PingSpoof", true), ["spoofping"] = new("PingSpoof", true),
        ["backtrack"] = new("Задержка входящих пакетов", true), ["lagrange"] = new("Задержка входящих пакетов", true),
    };

    private static readonly string[] Affixes = { "module", "mod", "feature", "hack", "cheat", "impl", "function", "func" };

    public void Run(ScanContext ctx)
    {
        var m = ctx.Model;
        var classHits = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var strongStr = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var weakStr = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var weakClass = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var c in m.OwnClasses)
        {
            if (c.Name.Contains('$')) continue;
            string norm = Norm(c.SimpleName);
            string stripped = Strip(norm);
            var sig = Names.GetValueOrDefault(norm) ?? Names.GetValueOrDefault(stripped);
            if (sig is not null)
            {
                bool moduleContext = sig.Strong || stripped != norm || IsModulePackage(c.Name) || SiblingModules(m, c);
                (moduleContext ? classHits : weakClass).Add2(sig.Signal, c.Name.Replace('/', '.'));
            }
            foreach (var mn in c.Methods)
                foreach (var s in mn.Strings)
                {
                    if (s.Length < 4 || s.Length > 24) continue;
                    string ns = Norm(s);
                    if (!Names.TryGetValue(ns, out var ss)) continue;
                    (ss.Strong ? strongStr : weakStr).Add2(ss.Signal, $"\"{s}\"  [{c.SimpleName}]");
                }
        }

        foreach (var signal in classHits.Keys.Concat(strongStr.Keys).Concat(weakStr.Keys).Concat(weakClass.Keys).Distinct())
        {
            var cls = classHits.GetValueOrDefault(signal) ?? new();
            var ss = strongStr.GetValueOrDefault(signal) ?? new();
            var ws = weakStr.GetValueOrDefault(signal) ?? new();
            var wc = weakClass.GetValueOrDefault(signal) ?? new();
            Severity sev = cls.Count > 0 || ss.Count > 0 ? Severity.High : wc.Count > 0 ? Severity.Medium : Severity.Low;
            if (sev == Severity.Low && ws.Count < 2 && wc.Count == 0) continue;
            var f = new Finding
            {
                Severity = sev, Category = "Названия", Analyzer = Name, Weight = sev == Severity.High ? 10 : sev == Severity.Medium ? 4 : 1,
                Signal = signal,
                Title = $"Модуль «{signal}» по названию" + (cls.Count > 0 ? $": класс {cls[0][(cls[0].LastIndexOf('.') + 1)..]}" : ss.Count > 0 ? $": строка {ss[0].Split("  [")[0]}" : ""),
                Why = sev == Severity.High
                    ? "Имя класса или строковая константа совпадает с названием читерской функции (так клиенты подписывают модули в меню). Поведенческие проверки ищут саму логику; если её не нашли — она, скорее всего, обфусцирована или вынесена."
                    : "Совпадение с названием функции неоднозначно (слово бывает и в честных модах), поэтому это лишь подсказка, где искать.",
            };
            if (cls.Count > 0) f.EvLines("Классы", cls.Take(15));
            if (wc.Count > 0) f.EvLines("Классы (неоднозначно)", wc.Take(15));
            if (ss.Count > 0) f.EvLines("Строки", ss.Distinct().Take(15));
            if (ws.Count > 0) f.EvLines("Строки (неоднозначно)", ws.Distinct().Take(15));
            ctx.Add(f);
        }
    }

    private static string Norm(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char ch in s) if (char.IsLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
        return sb.ToString();
    }

    private static string Strip(string n)
    {
        foreach (var a in Affixes)
        {
            if (n.Length > a.Length + 2 && n.EndsWith(a)) return n[..^a.Length];
            if (n.Length > a.Length + 2 && n.StartsWith(a)) return n[a.Length..];
        }
        return n;
    }

    private static bool IsModulePackage(string name)
    {
        string p = name.ToLowerInvariant();
        return p.Contains("/module") || p.Contains("/combat/") || p.Contains("/hack") || p.Contains("/cheat") || p.Contains("/features/") || p.Contains("/feature/") || p.Contains("/functions/");
    }

    /// <summary>Класс лежит среди «модулей» — у соседей общий суперкласс, наследников много.</summary>
    private static bool SiblingModules(ModModel m, ClassNode c)
    {
        string? sup = c.Cf.Super;
        if (sup is null || sup == "java/lang/Object" || !m.Classes.ContainsKey(sup)) return false;
        return m.Classes.Values.Count(x => x.Cf.Super == sup) >= 8;
    }
}

internal static class DictExt
{
    public static void Add2(this Dictionary<string, List<string>> d, string k, string v)
    {
        if (!d.TryGetValue(k, out var l)) d[k] = l = new List<string>();
        if (!l.Contains(v)) l.Add(v);
    }
}
