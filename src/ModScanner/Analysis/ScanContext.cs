using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner.Analysis;

/// <summary>Контекст проверки одного jar.</summary>
internal sealed class ScanContext
{
    public ModUnit Unit = null!;
    public ModModel Model = null!;
    public GameNames Names = null!;
    public bool Verified;                       // файл побайтно совпал с релизом на Modrinth
    public List<Finding> Findings = new();

    public void Add(Finding f) => Findings.Add(f);

    public bool HasSignal(string signal, Severity atLeast) => Findings.Any(f => f.Signal == signal && f.Severity >= atLeast);
}

internal interface IAnalyzer
{
    string Name { get; }
    void Run(ScanContext ctx);
}

/// <summary>Общие помощники анализаторов.</summary>
internal static class Ev
{
    public static IEnumerable<string> Atoms(ModModel m, MethodNode root, params int[] atoms)
    {
        foreach (var a in atoms)
            if (root.Closure.Has(a)) yield return m.Explain(root, a);
    }

    public static string Where(ModModel m, MethodNode mn) =>
        $"{m.Label(mn)}\nкласс {mn.Owner.Name.Replace('/', '.')}" + (mn.AsHook is not null ? $"\nинъекция: {mn.AsHook.Describe()}" : "");
}
