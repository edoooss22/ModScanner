namespace ModScanner.Report;

internal enum Severity { Info, Low, Medium, High, Critical }

/// <summary>Блок доказательства в карточке находки: заголовок и текст (обычно моноширинный).</summary>
internal sealed class Evidence
{
    public string Title = "";
    public string Text = "";
    public Evidence(string title, string text) { Title = title; Text = text; }
}

/// <summary>Одна находка проверки. Category — вкладка/фильтр; Signal — короткий ярлык вида «TriggerBot».</summary>
internal sealed class Finding
{
    public Severity Severity;
    public string Category = "";
    public string Analyzer = "";
    public string Title = "";
    public string Why = "";                 // почему это подозрительно (человеку)
    public string? Signal;                  // короткий ярлык вида для сводки: TriggerBot, Кража сессии…
    public double Weight;                   // вклад в итоговый балл мода
    public string Location = "";            // класс/метод/файл, где найдено
    public List<Evidence> Evidence = new();
    public List<string> Tags = new();

    public Finding Ev(string title, string text) { Evidence.Add(new Evidence(title, text)); return this; }
    public Finding EvLines(string title, IEnumerable<string> lines) { Evidence.Add(new Evidence(title, string.Join("\n", lines))); return this; }
}
