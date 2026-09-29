using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using ModScanner.Analysis;

namespace ModScanner.Gui;

/// <summary>Минималистичное окно: выбрать, что проверить, → прогресс → открыть отчёт.</summary>
internal sealed class MainForm : Form
{
    private readonly ActionCard _pickCard, _hereCard;
    private readonly Toggle _offline;
    private readonly Label _status, _counter, _hint;
    private readonly CountsLine _summary;
    private readonly ProgressLine _bar;
    private readonly ListBox _list;
    private readonly PillButton _stop, _openReport, _openBrowser;
    private readonly Panel _body;
    private readonly Label _empty;

    private CancellationTokenSource? _cts;
    private string? _summaryPath;
    private readonly List<FileResult> _results = new();
    private readonly ScanOptions _opts = new();

    /// <summary>Что умеет обнаруживать сканер — для подзаголовка.</summary>
    private static readonly string[] Detects =
    {
        "KillAura", "TriggerBot", "HitBox", "Reach", "AimAssist", "Внешняя авторизация", "Загрузка кода с сервера",
        "FakeLag / Blink", "PingSpoof", "Задержка входящих пакетов", "Скачивание и запуск файлов", "Кража данных (стилер)",
        "Кража токена сессии", "Отправка на Discord-вебхук",
    };

    private const string GlyphFolder = "\uE8B7", GlyphHere = "\uE8DA";

    public MainForm()
    {
        AutoScaleMode = AutoScaleMode.None;         // раскладка задана в пикселях 96 DPI и масштабируется вручную ниже
        Text = "ModScanner";
        BackColor = Theme.Bg;
        ForeColor = Theme.Fg;
        Font = Theme.Body;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(860, 652);
        ShowIcon = false;
        AllowDrop = true;

        _body = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg, Padding = new Padding(24) };
        Controls.Add(_body);

        var title = new Label { Text = "ModScanner", Font = Theme.Title, ForeColor = Theme.Fg, AutoSize = true, Location = new Point(22, 18), BackColor = Theme.Bg };
        var sub = new Label
        {
            Text = $"v{Program.Version}  ·  Обнаружение: {string.Join(", ", Detects)}",
            Font = Theme.Small, ForeColor = Theme.Fg3, AutoSize = true, MaximumSize = new Size(812, 0), Location = new Point(25, 56), BackColor = Theme.Bg,
        };
        _body.Controls.Add(title);
        _body.Controls.Add(sub);

        int cw = (860 - 48 - 14) / 2;
        _pickCard = Card(GlyphFolder, "Выбрать папку", "Папка mods или любая папка с .jar — проверяются все jar внутри, включая подпапки", 24);
        _hereCard = Card(GlyphHere, "Папка программы", "Все .jar рядом с ModScanner.exe:  " + ShortPath(AppContext.BaseDirectory), 24 + cw + 14);
        foreach (var c in new[] { _pickCard, _hereCard }) { c.Size = new Size(cw, 132); c.Top = 104; _body.Controls.Add(c); }
        _pickCard.Click += (_, _) => PickFolder();
        _hereCard.Click += (_, _) => ScanPaths(new[] { AppContext.BaseDirectory }, "папка программы");

        _offline = new Toggle { Text = "Без сети (без сверки с Modrinth)", Location = new Point(24, 254), Size = new Size(380, 24) };
        _hint = new Label { Text = "или перетащите папку / .jar в окно", Font = Theme.Small, ForeColor = Theme.Fg3, AutoSize = true, BackColor = Theme.Bg };
        _body.Controls.Add(_offline);
        _body.Controls.Add(_hint);
        _hint.Location = new Point(860 - 24 - TextRenderer.MeasureText(_hint.Text, Theme.Small).Width, 258);

        _status = new Label { Text = "Выберите, что проверить.", Font = Theme.BodyBold, ForeColor = Theme.Fg, AutoEllipsis = true, Location = new Point(24, 296), Size = new Size(620, 22), BackColor = Theme.Bg };
        _counter = new Label { Text = "", Font = Theme.Small, ForeColor = Theme.Fg3, TextAlign = ContentAlignment.MiddleRight, Location = new Point(644, 296), Size = new Size(192, 22), BackColor = Theme.Bg };
        _bar = new ProgressLine { Location = new Point(24, 324), Size = new Size(812, 6) };
        _body.Controls.AddRange(new Control[] { _status, _counter, _bar });

        var frame = new Panel { Location = new Point(24, 344), Size = new Size(812, 228), BackColor = Theme.Line, Padding = new Padding(1) };
        _list = new ListBox
        {
            Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = Theme.Bg2, ForeColor = Theme.Fg,
            DrawMode = DrawMode.OwnerDrawFixed, ItemHeight = 32, IntegralHeight = false, Font = Theme.Body,
        };
        _list.DrawItem += DrawRow;
        _list.DoubleClick += (_, _) => { if (_list.SelectedItem is FileResult fr) ShowInFolder(fr.Path); };
        _list.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter && _list.SelectedItem is FileResult fr) ShowInFolder(fr.Path); };
        frame.Controls.Add(_list);
        _empty = new Label
        {
            Text = "Здесь появятся результаты проверки", Font = Theme.Body, ForeColor = Theme.Fg3, BackColor = Theme.Bg2,
            Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter,
        };
        frame.Controls.Add(_empty);
        _empty.BringToFront();
        _body.Controls.Add(frame);

        _summary = new CountsLine { Location = new Point(24, 592), Size = new Size(528, 40), BackColor = Theme.Bg };
        _stop = new PillButton { Text = "Остановить", Glyph = "", Size = new Size(146, 36), Location = new Point(690, 594), Visible = false };
        _openBrowser = new PillButton { Text = "В браузере", Glyph = "", Size = new Size(126, 36), Location = new Point(560, 594), Enabled = false };
        _openReport = new PillButton { Text = "Открыть отчёт", Glyph = "", Primary = true, Size = new Size(146, 36), Location = new Point(690, 594), Enabled = false };
        _stop.Click += (_, _) => { _cts?.Cancel(); _stop.Enabled = false; _status.Text = "Останавливаю… отчёт будет по уже проверенным файлам."; };
        _openReport.Click += (_, _) => { if (_summaryPath is not null) ShowInFolder(_summaryPath); };
        _openBrowser.Click += (_, _) => { if (_summaryPath is not null) Open(_summaryPath); };
        _body.Controls.AddRange(new Control[] { _summary, _stop, _openBrowser, _openReport });

        // шрифты заданы в пунктах и уже учитывают DPI; координаты и размеры — пересчитываем
        float k = DeviceDpi / 96f;
        if (Math.Abs(k - 1f) > 0.01f) Scale(new SizeF(k, k));

        DragEnter += (_, e) => { if (!Busy && e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) => { if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0) ScanPaths(paths, paths.Length == 1 ? Path.GetFileName(paths[0].TrimEnd('\\')) : $"{paths.Length} объектов"); };
    }

    private bool Busy => _cts is not null;

    private ActionCard Card(string glyph, string caption, string hint, int x) => new() { Glyph = glyph, Caption = caption, Hint = hint, Left = x };

    // ------------------------------------------------------------------ действия

    private void PickFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = "Папка с модами (.jar)", UseDescriptionForTitle = true, ShowNewFolderButton = false };
        string mods = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".minecraft", "mods");
        if (Directory.Exists(mods)) dlg.InitialDirectory = mods;
        if (dlg.ShowDialog(this) == DialogResult.OK) ScanPaths(new[] { dlg.SelectedPath }, dlg.SelectedPath);
    }

    private void ScanPaths(string[] paths, string what)
    {
        var skip = new[] { _opts.CacheDir, _opts.OutDir };
        Start($"Поиск .jar: {what}", ct =>
        {
            var jars = ScanRunner.CollectJars(paths);
            return jars.Where(j => !skip.Any(s => j.StartsWith(Path.GetFullPath(s), StringComparison.OrdinalIgnoreCase))).ToList();
        });
    }

    private async void Start(string searching, Func<CancellationToken, List<string>> discover)
    {
        if (Busy) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true);
        _results.Clear();
        _list.Items.Clear();
        _empty.Text = "Идёт проверка…";
        _empty.Visible = true;
        _summaryPath = null;
        _summary.Set();
        _summary.Visible = false;
        _status.Text = searching;
        _counter.Text = "";
        _bar.BarColor = Theme.Accent;
        _bar.Indeterminate = true;
        _opts.Offline = _offline.On;

        var progress = new Progress<ScanProgress>(OnProgress);
        ScanOutcome? outcome = null;
        string? error = null;
        int found = 0;
        try
        {
            outcome = await Task.Run(() =>
            {
                var jars = discover(ct);
                found = jars.Count;
                if (jars.Count == 0 || ct.IsCancellationRequested) return null;
                return ScanRunner.Run(jars, _opts, progress, ct);
            });
        }
        catch (Exception ex) { error = ex.Message; }

        _bar.Indeterminate = false;
        if (error is not null) { _status.Text = "Ошибка: " + error; _bar.Value = 0; _empty.Text = "Ошибка проверки"; }
        else if (outcome is null) { _status.Text = ct.IsCancellationRequested ? "Остановлено." : "Не найдено ни одного .jar."; _bar.Value = 0; _counter.Text = ""; _empty.Text = "Нет файлов для проверки"; }
        else Finish(outcome, found);
        _cts.Dispose();
        _cts = null;
        SetBusy(false);
    }

    private void OnProgress(ScanProgress p)
    {
        if (p.Total > 0 && p.Stage == "Проверка")
        {
            _bar.Indeterminate = false;
            _bar.Value = (float)p.Done / p.Total;
            _counter.Text = $"{p.Done} из {p.Total}";
            if (p.Result is null && p.Error is null) _status.Text = "Проверка: " + Path.GetFileName(p.File);
        }
        else _status.Text = p.Stage + "…";
        if (p.Result is not null)
        {
            _results.Add(p.Result);
            _empty.Visible = false;
            _list.Items.Add(p.Result);
            _list.TopIndex = Math.Max(0, _list.Items.Count - 1);
            if (p.Result.Verdict >= Verdict.Suspicious) _bar.BarColor = p.Result.Verdict == Verdict.Cheat ? Theme.Crit : Theme.High;
        }
    }

    private void Finish(ScanOutcome o, int found)
    {
        _summaryPath = o.SummaryPath;
        _bar.Value = 1;
        int cheat = o.Results.Count(r => r.Verdict == Verdict.Cheat), susp = o.Results.Count(r => r.Verdict == Verdict.Suspicious),
            review = o.Results.Count(r => r.Verdict == Verdict.Review), clean = o.Results.Count - cheat - susp - review;
        _status.Text = o.Cancelled ? $"Остановлено — проверено {o.Results.Count} из {found}" : $"Готово — проверено {o.Results.Count} файлов";
        _counter.Text = "";
        if (cheat + susp + review == 0) _summary.Set(("читерских функций не найдено", Theme.Ok));
        else _summary.Set(new[] { (cheat, "читов", Theme.Crit), (susp, "подозрительных", Theme.High), (review, "проверить", Theme.Med), (clean, "чистых", Theme.Ok) }
            .Where(x => x.Item1 > 0).Select(x => ($"{x.Item2}: {x.Item1}", x.Item3)).ToArray());
        _summary.Visible = true;
        _bar.BarColor = cheat > 0 ? Theme.Crit : susp > 0 ? Theme.High : review > 0 ? Theme.Med : Theme.Ok;
        // по окончании — самые важные сверху
        var ordered = _results.OrderBy(r => ScanRunner.Rank(r.Verdict)).ThenBy(r => r.FileName, StringComparer.OrdinalIgnoreCase).ToList();
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var r in ordered) _list.Items.Add(r);
        _list.EndUpdate();
        _openReport.Enabled = _openBrowser.Enabled = File.Exists(_summaryPath);
        if (_list.Items.Count == 0) { _empty.Text = "Ни один файл не проверен"; _empty.Visible = true; }
    }

    private void SetBusy(bool busy)
    {
        _pickCard.Enabled = _hereCard.Enabled = _offline.Enabled = !busy;
        _stop.Visible = busy;
        _stop.Enabled = busy;
        if (busy) _openReport.Enabled = _openBrowser.Enabled = false;
        _openReport.Visible = _openBrowser.Visible = !busy;
        _hint.Visible = !busy;
    }

    // ------------------------------------------------------------------ отрисовка строки списка

    private void DrawRow(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0 || _list.Items[e.Index] is not FileResult fr) return;
        var g = e.Graphics;
        Theme.Hq(g);
        bool sel = (e.State & DrawItemState.Selected) != 0;
        using (var bg = new SolidBrush(sel ? Theme.Bg3 : Theme.Bg2)) g.FillRectangle(bg, e.Bounds);
        using (var sep = new Pen(Theme.Line)) g.DrawLine(sep, e.Bounds.Left + 12, e.Bounds.Bottom - 1, e.Bounds.Right - 12, e.Bounds.Bottom - 1);

        var (text, color) = fr.Verdict switch
        {
            Verdict.Cheat => ("ЧИТ", Theme.Crit),
            Verdict.Suspicious => ("ПОДОЗРИТ.", Theme.High),
            Verdict.Review => ("ПРОВЕРИТЬ", Theme.Med),
            Verdict.Verified => ("MODRINTH", Theme.Verified),
            _ => ("ЧИСТО", Theme.Ok),
        };
        float k = DeviceDpi / 96f;
        var pill = new RectangleF(e.Bounds.Left + 12 * k, e.Bounds.Top + (e.Bounds.Height - 18 * k) / 2, 84 * k, 18 * k);
        using (var pp = Theme.Round(pill, 5 * k))
        using (var pb = new SolidBrush(Color.FromArgb(38, color)))
            g.FillPath(pb, pp);
        TextRenderer.DrawText(g, text, Theme.Tiny, Rectangle.Round(pill), color, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);

        int x = e.Bounds.Left + (int)(108 * k);
        string name = fr.FileName;
        var mr = fr.Root.Modrinth;
        bool renamed = mr is { Found: true } && mr.FileName.Length > 0 && !string.Equals(mr.FileName, fr.FileName, StringComparison.OrdinalIgnoreCase);
        int nameW = Math.Min(TextRenderer.MeasureText(g, name, Theme.Body).Width, (int)(330 * k));
        TextRenderer.DrawText(g, name, Theme.Body, new Rectangle(x, e.Bounds.Top, nameW, e.Bounds.Height), Theme.Fg, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        x += nameW + 10;
        string extra = fr.Signals.Count > 0 ? string.Join(" · ", fr.Signals)
                     : renamed ? $"переименован · на Modrinth: {mr!.ProjectTitle} {mr.VersionNumber} — {mr.FileName}"
                     : mr is { Found: true } ? $"{mr.ProjectTitle} {mr.VersionNumber}" : "";
        if (renamed && fr.Signals.Count > 0) extra += $"  ·  на Modrinth: {mr!.ProjectTitle}";
        int timeW = (int)(58 * k);
        TextRenderer.DrawText(g, extra, Theme.Small, new Rectangle(x, e.Bounds.Top, e.Bounds.Right - x - timeW - 4, e.Bounds.Height),
            fr.Signals.Count > 0 ? Theme.Mix(color, Theme.Fg2, 0.35f) : renamed ? Theme.High : Theme.Fg3, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        TextRenderer.DrawText(g, $"{fr.Elapsed.TotalSeconds:0.0}s", Theme.Small, new Rectangle(e.Bounds.Right - timeW, e.Bounds.Top, timeW - (int)(12 * k), e.Bounds.Height),
            Theme.Fg3, TextFormatFlags.VerticalCenter | TextFormatFlags.Right | TextFormatFlags.NoPadding);
    }

    // ------------------------------------------------------------------ окно

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try { int on = 1; DwmSetWindowAttribute(Handle, 20, ref on, 4); } catch { }        // тёмный заголовок окна
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        _list.ItemHeight = (int)(32 * DeviceDpi / 96f);
        _hint.Left = _bar.Right - _hint.Width;
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        try { SetWindowTheme(_list.Handle, "DarkMode_Explorer", null); } catch { }         // тёмная полоса прокрутки
        _ = Task.Run(() => { try { ScanRunner.Names(); } catch { } });                      // таблица имён — заранее
    }

    protected override void OnFormClosing(FormClosingEventArgs e) { _cts?.Cancel(); base.OnFormClosing(e); }

    /// <summary>Отладка вида: отрисовать окно в PNG (пустое или после проверки папки).</summary>
    public static void Snapshot(string png, string? scanDir)
    {
        using var f = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(-3000, -3000), ShowInTaskbar = false };
        f.Show();
        Application.DoEvents();
        if (scanDir == "::busy")
        {
            f.SetBusy(true);
            f._status.Text = "Проверка: meteor-client-26.2-25.jar";
            f._counter.Text = "7 из 19";
            f._bar.Value = 7 / 19f;
        }
        else if (scanDir is not null)
        {
            var jars = ScanRunner.CollectJars(new[] { scanDir });
            var o = ScanRunner.Run(jars, new ScanOptions { OutDir = Path.Combine(Path.GetTempPath(), "modscan-snap") }, new SyncProgress<ScanProgress>(f.OnProgress));
            f.Finish(o, jars.Count);
            f.SetBusy(false);
        }
        Application.DoEvents();
        using var bmp = new Bitmap(f.Width, f.Height);
        f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
        bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
    }

    /// <summary>Открыть папку в Проводнике и выделить в ней файл (пути с кириллицей и пробелами — как есть).</summary>
    private static void ShowInFolder(string path)
    {
        try
        {
            string full = Path.GetFullPath(path);
            if (File.Exists(full))
                Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select," + full }, UseShellExecute = false });
            else if (Directory.Exists(Path.GetDirectoryName(full)))
                Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { Path.GetDirectoryName(full)! }, UseShellExecute = false });
        }
        catch { }
    }

    private static void Open(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch { }
    }

    private static string ShortPath(string p)
    {
        p = p.TrimEnd('\\');
        return p.Length <= 60 ? p : p[..3] + "…" + p[^56..];
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hwnd, string app, string? idList);
}
