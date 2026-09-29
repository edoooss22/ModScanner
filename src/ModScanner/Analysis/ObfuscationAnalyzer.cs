using ModScanner.Core;
using ModScanner.Report;
using static ModScanner.Analysis.Vocab;

namespace ModScanner.Analysis;

/// <summary>
/// Обфускация и «тёмные» возможности (нативный код, Java-агент, запуск процессов) — контекст.
/// Сами по себе не чит, но объясняют, почему смысловые проверки могли промолчать, и повышают интерес
/// к моду, которого нет на Modrinth.
/// </summary>
internal sealed class ObfuscationAnalyzer : IAnalyzer
{
    public string Name => "Обфускация";

    public void Run(ScanContext ctx)
    {
        var m = ctx.Model;
        var own = m.OwnClasses.ToList();

        // 1. имена, которые не создаёт компилятор
        var illegal = new List<string>();
        foreach (var c in own)
        {
            if (Illegal(c.SimpleName)) illegal.Add("класс " + c.Name);
            foreach (var f in c.Cf.Fields) if (Illegal(f.Name)) illegal.Add($"{c.SimpleName}.{f.Name} (поле)");
            foreach (var mm in c.Cf.Methods) if (Illegal(mm.Name) && mm.Name is not ("<init>" or "<clinit>")) illegal.Add($"{c.SimpleName}.{mm.Name}() (метод)");
        }
        if (illegal.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, Category = "Обфускация", Analyzer = Name, Weight = 5, Signal = "Обфускация",
                Title = $"Имена, которые не создаёт компилятор ({illegal.Count})",
                Why = "Имена классов, полей или методов содержат символы, недопустимые в исходном коде Java. Это ручная обфускация, которой прячут назначение кода.",
            }.EvLines("Имена", illegal.Take(40)));

        // 2. шифрование строк: строка собирается из массива в цикле с XOR
        var enc = own.Where(StringDecryptor).ToList();
        if (enc.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Medium, Category = "Обфускация", Analyzer = Name, Weight = 4, Signal = "Шифрование строк",
                Title = $"Строки расшифровываются во время работы ({Plural.Cls(enc.Count)})",
                Why = "Методы собирают строку из массива чисел/символов в цикле с побитовым XOR — строковые константы (адреса серверов, названия модулей) зашифрованы и восстанавливаются только в рантайме.",
            }.EvLines("Классы", enc.Take(30).Select(c => c.Name.Replace('/', '.'))));

        // 3. массовые короткие имена
        int total = own.Count;
        var single = own.Where(c => !c.Name.Contains('$') && c.SimpleName.Length <= 2).ToList();
        if (total >= 6 && single.Count >= Math.Max(4, total * 0.4))
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Обфускация", Analyzer = Name, Weight = 2,
                Title = $"Много одно-двухбуквенных имён классов ({single.Count} из {total})",
                Why = "Значительная часть классов названа одной-двумя буквами: мод прогнан через обфускатор.",
            }.EvLines("Классы", single.Take(30).Select(c => c.Name)));

        // 4. возможности, требующие внимания (контекст)
        var native = own.Where(c => c.Cf.Methods.Any(x => x.IsNative) || c.Methods.Any(x => x.Direct.Has(NativeLoad))).ToList();
        if (native.Count > 0)
        {
            bool nativeObf = own.Count(c => c.Cf.Methods.Any(x => x.IsNative)) >= 5 && own.Any(c => c.Methods.Any(x => x.Direct.Has(NativeLoad)));
            ctx.Add(new Finding
            {
                Severity = nativeObf ? Severity.Medium : Severity.Low, Category = "Обфускация", Analyzer = Name, Weight = nativeObf ? 4 : 1,
                Signal = nativeObf ? "Нативная защита" : null,
                Title = nativeObf ? $"Логика вынесена в нативный код ({Plural.Cls(native.Count)})" : $"Нативный код ({Plural.Cls(native.Count)})",
                Why = nativeObf
                    ? "Много классов с native-методами и загрузчик нативной библиотеки: байт-код методов перенесён в DLL (нативная обфускация). Такую логику нельзя проверить по jar — обычно так защищают платные чит-клиенты."
                    : "Мод подключает нативную библиотеку или объявляет native-методы. Бывает у честных модов (звук, графика), проверьте назначение.",
            }.EvLines("Классы", native.Take(20).Select(c => c.Name.Replace('/', '.'))));
        }
        var agent = own.Where(c => c.Methods.Any(x => x.Direct.Has(Instrument)) || c.Cf.Methods.Any(x => x.Name is "agentmain" or "premain")).ToList();
        if (agent.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Обфускация", Analyzer = Name, Weight = 1,
                Title = $"Java-агент / Instrumentation ({Plural.Cls(agent.Count)})",
                Why = "Мод может переписывать байт-код уже загруженных классов. Иногда так работают честные библиотеки; в сочетании с другими признаками — способ скрыть логику.",
            }.EvLines("Классы", agent.Take(10).Select(c => c.Name.Replace('/', '.'))));
        var proc = own.Where(c => c.Methods.Any(x => x.Direct.Has(Process))).ToList();
        if (proc.Count > 0)
            ctx.Add(new Finding
            {
                Severity = Severity.Low, Category = "Обфускация", Analyzer = Name, Weight = 1,
                Title = $"Запуск процессов ОС ({Plural.Cls(proc.Count)})",
                Why = "Мод запускает внешние программы (ProcessBuilder / Runtime.exec). Для мода к игре необычно; посмотрите, что именно запускается.",
            }.EvLines("Где", proc.Take(10).SelectMany(c => c.Methods.Where(x => x.Direct.Has(Process)).Take(1).Select(x => m.Explain(x, Process) + $"  [{c.SimpleName}.{x.Name}]"))));
    }

    private static bool Illegal(string name)
    {
        foreach (char c in name)
            if (c is '?' or ' ' or ';' or '[' || char.IsControl(c) || (c > 0x7e && !char.IsLetter(c))) return true;
        return false;
    }

    /// <summary>Метод-расшифровщик: цикл (обратный переход) + XOR + сборка строки из массива.</summary>
    private static bool StringDecryptor(ClassNode c)
    {
        foreach (var mn in c.Methods)
        {
            if (!mn.Mi.Desc.EndsWith(")Ljava/lang/String;")) continue;
            var ins = mn.Mi.Insns;
            bool back = ins.Any(i => (i.Op == Bytecode.GOTO || i.Op == Bytecode.GOTO_W || Bytecode.IsBranch(i.Op)) && i.Operand < i.Pc);
            if (!back) continue;
            int xor = ins.Count(i => Bytecode.IsXor(i.Op));
            bool arr = ins.Any(i => i.Op is 46 or 50 or 52 or 51);          // iaload / aaload / caload / baload
            bool build = ins.Any(i => i.Op == Bytecode.INVOKESPECIAL && c.Cf.Member(i.Operand) is { Owner: "java/lang/String", Name: "<init>" })
                         || ins.Any(i => Bytecode.IsInvoke(i.Op) && i.Op != Bytecode.INVOKEDYNAMIC && c.Cf.Member(i.Operand) is { Owner: "java/lang/StringBuilder", Name: "append" });
            if (xor >= 1 && arr && build) return true;
        }
        return false;
    }
}
