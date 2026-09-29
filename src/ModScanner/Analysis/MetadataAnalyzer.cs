using ModScanner.Core;
using ModScanner.Report;

namespace ModScanner.Analysis;

/// <summary>Согласованность метаданных Fabric и то, какой код объявлен точкой входа мода.</summary>
internal sealed class MetadataAnalyzer : IAnalyzer
{
    public string Name => "Метаданные";

    public void Run(ScanContext ctx)
    {
        var u = ctx.Unit;

        // конфигурации Mixin: заявлены, но класса-миксина нет в jar
        foreach (var mc in u.MixinConfigs)
        {
            var missing = mc.AllMixinClasses.Where(c => !u.ByName.ContainsKey(c)).ToList();
            if (missing.Count > 0 && missing.Count == mc.AllMixinClasses.Count() && mc.AllMixinClasses.Any())
                ctx.Add(new Finding
                {
                    Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1.5,
                    Title = $"Конфигурация Mixin {mc.Path} ссылается на отсутствующие классы",
                    Why = "В конфигурации Mixin перечислены классы, которых нет в архиве. Бывает при небрежной пересборке.",
                }.EvLines("Отсутствуют", missing.Take(20)));
        }

        // точка входа объявлена, но класса нет
        if (u.Fabric is not null)
        {
            var missing = u.Fabric.AllEntrypointClasses
                .Select(c => c.Split("::")[0].Replace('.', '/'))
                .Where(c => c.Length > 0 && !u.ByName.ContainsKey(c)).Distinct().ToList();
            if (missing.Count > 0)
                ctx.Add(new Finding
                {
                    Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1,
                    Title = $"Точка входа ссылается на отсутствующий класс ({missing.Count})",
                    Why = "В fabric.mod.json объявлена точка входа, но её класса нет в архиве.",
                }.EvLines("Классы", missing));
        }

        // access widener, открывающий доступ к внутренностям игры
        if (u.Fabric?.AccessWidener is not null)
        {
            var aw = u.Zip.Read(u.Fabric.AccessWidener);
            if (aw is not null)
            {
                int lines = System.Text.Encoding.UTF8.GetString(aw).Split('\n').Count(l => l.TrimStart().StartsWith("accessible") || l.TrimStart().StartsWith("mutable"));
                if (lines >= 20)
                    ctx.Add(new Finding
                    {
                        Severity = Severity.Low, Category = "Целостность", Analyzer = Name, Weight = 1.5,
                        Title = $"Access widener открывает много внутренних членов игры ({lines})",
                        Why = "Мод широко открывает доступ к закрытым полям и методам игры. Само по себе законно, но в сочетании с другими признаками расширяет возможности вмешательства.",
                    });
            }
        }
    }
}
