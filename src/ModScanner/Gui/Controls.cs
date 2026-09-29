using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;

namespace ModScanner.Gui;

/// <summary>Палитра — та же, что в HTML-отчётах.</summary>
internal static class Theme
{
    public static readonly Color Bg = Hex("#0f1216"), Bg2 = Hex("#161a20"), Bg3 = Hex("#1d222a"), Line = Hex("#272d37");
    public static readonly Color Fg = Hex("#e6e9ef"), Fg2 = Hex("#a4adbb"), Fg3 = Hex("#6b7482");
    public static readonly Color Crit = Hex("#f0454b"), High = Hex("#f59f00"), Med = Hex("#22b8cf"), Ok = Hex("#37b24d");
    public static readonly Color Accent = Hex("#4c8dff"), Verified = Hex("#20c997");

    public static readonly Font Title = new("Segoe UI Semibold", 17f);
    public static readonly Font Body = new("Segoe UI", 9.75f);
    public static readonly Font BodyBold = new("Segoe UI Semibold", 10.25f);
    public static readonly Font Small = new("Segoe UI", 8.75f);
    public static readonly Font Tiny = new("Segoe UI Semibold", 7.5f);
    public static readonly Font Icons = new("Segoe MDL2 Assets", 17f);

    public static Color Hex(string h) => ColorTranslator.FromHtml(h);
    public static Color Mix(Color a, Color b, float t) =>
        Color.FromArgb((int)(a.R + (b.R - a.R) * t), (int)(a.G + (b.G - a.G) * t), (int)(a.B + (b.B - a.B) * t));

    public static GraphicsPath Round(RectangleF r, float rad)
    {
        var p = new GraphicsPath();
        float d = rad * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public static void Hq(Graphics g)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    }
}

/// <summary>Базовый элемент без мерцания с собственной отрисовкой.</summary>
internal abstract class Painted : Control
{
    protected bool Hover, Down;
    /// <summary>Коэффициент DPI (1 при 100 %).</summary>
    protected float K => DeviceDpi / 96f;

    protected Painted()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Theme.Bg;
        ForeColor = Theme.Fg;
        Cursor = Cursors.Hand;
    }

    protected override void OnMouseEnter(EventArgs e) { Hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { Hover = false; Down = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { Down = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { Down = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnEnabledChanged(EventArgs e) { Cursor = Enabled ? Cursors.Hand : Cursors.Default; Invalidate(); base.OnEnabledChanged(e); }
}

/// <summary>Карточка-действие: значок, заголовок, пояснение.</summary>
internal sealed class ActionCard : Painted
{
    public string Glyph = "", Caption = "", Hint = "";

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        bool on = Enabled && Hover;
        using (var path = Theme.Round(r, 10 * K))
        {
            using var fill = new SolidBrush(!Enabled ? Theme.Bg2 : Down ? Theme.Mix(Theme.Bg2, Theme.Accent, 0.16f) : on ? Theme.Mix(Theme.Bg2, Theme.Accent, 0.08f) : Theme.Bg2);
            g.FillPath(fill, path);
            using var pen = new Pen(on ? Theme.Mix(Theme.Line, Theme.Accent, 0.75f) : Theme.Line);
            g.DrawPath(pen, path);
        }
        var fg = Enabled ? Theme.Fg : Theme.Fg3;
        // значок в скруглённом квадрате
        float k = K;
        int pad = (int)(16 * k);
        var ib = new RectangleF(pad, pad, 36 * k, 36 * k);
        using (var ip = Theme.Round(ib, 8 * k))
        using (var ibr = new SolidBrush(Enabled ? Color.FromArgb(40, Theme.Accent) : Theme.Bg3))
            g.FillPath(ibr, ip);
        TextRenderer.DrawText(g, Glyph, Theme.Icons, Rectangle.Round(ib), Enabled ? Theme.Accent : Theme.Fg3,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        int capY = (int)(ib.Bottom + 10 * k);
        int capH = TextRenderer.MeasureText(g, "Ag", Theme.BodyBold).Height;
        TextRenderer.DrawText(g, Caption, Theme.BodyBold, new Rectangle(pad, capY, Width - 2 * pad, capH), fg, TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        TextRenderer.DrawText(g, Hint, Theme.Small, new Rectangle(pad, capY + capH + (int)(2 * k), Width - 2 * pad, Height - capY - capH - pad), Enabled ? Theme.Fg2 : Theme.Fg3,
            TextFormatFlags.Left | TextFormatFlags.WordBreak | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
    }
}

/// <summary>Скруглённая кнопка: акцентная или «призрачная».</summary>
internal sealed class PillButton : Painted
{
    public bool Primary;
    public string Glyph = "";

    private static readonly Font GlyphFont = new("Segoe MDL2 Assets", 10f);
    public PillButton() { Font = Theme.Body; Height = 34; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        Color fill, border, fg;
        if (!Enabled) { fill = Theme.Bg2; border = Theme.Line; fg = Theme.Fg3; }
        else if (Primary)
        {
            fill = Down ? Theme.Mix(Theme.Accent, Color.Black, 0.2f) : Hover ? Theme.Mix(Theme.Accent, Color.White, 0.1f) : Theme.Accent;
            border = fill; fg = Color.White;
        }
        else
        {
            fill = Down ? Theme.Bg3 : Hover ? Theme.Mix(Theme.Bg2, Theme.Fg, 0.05f) : Theme.Bg2;
            border = Hover ? Theme.Fg3 : Theme.Line; fg = Hover ? Theme.Fg : Theme.Fg2;
        }
        using (var path = Theme.Round(r, 8 * K))
        {
            using var b = new SolidBrush(fill);
            g.FillPath(b, path);
            using var p = new Pen(border);
            g.DrawPath(p, path);
        }
        string text = Text;
        var size = TextRenderer.MeasureText(g, text, Font, Size.Empty, TextFormatFlags.NoPadding);
        int glyphW = Glyph.Length > 0 ? (int)(22 * K) : 0;
        int x = (Width - size.Width - glyphW) / 2;
        if (glyphW > 0)
            TextRenderer.DrawText(g, Glyph, GlyphFont, new Rectangle(x, 0, glyphW, Height), fg, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
        TextRenderer.DrawText(g, text, Font, new Rectangle(x + glyphW, 0, size.Width + 4, Height), fg, TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding);
    }

    protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }
}

/// <summary>Тонкая полоса прогресса со скруглением; в неопределённом режиме бегает отрезок.</summary>
internal sealed class ProgressLine : Control
{
    private float _value;
    private bool _indeterminate;
    private float _phase;
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 16 };
    public Color BarColor = Theme.Accent;

    public ProgressLine()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Height = 6;
        _timer.Tick += (_, _) => { _phase = (_phase + 0.012f) % 1.6f; Invalidate(); };
    }

    public float Value { get => _value; set { _value = Math.Clamp(value, 0, 1); Invalidate(); } }

    public bool Indeterminate
    {
        get => _indeterminate;
        set { _indeterminate = value; if (value) _timer.Start(); else _timer.Stop(); Invalidate(); }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        var r = new RectangleF(0, 0, Width - 1, Height - 1);
        using (var track = Theme.Round(r, (Height - 1) / 2f))
        using (var tb = new SolidBrush(Theme.Bg3))
            g.FillPath(tb, track);
        RectangleF fill;
        if (_indeterminate)
        {
            float w = Width * 0.28f;
            float x = (_phase - 0.3f) * Width;
            fill = RectangleF.Intersect(new RectangleF(x, 0, w, Height - 1), r);
        }
        else fill = new RectangleF(0, 0, (Width - 1) * _value, Height - 1);
        if (fill.Width < 2) return;
        using var fp = Theme.Round(fill, (Height - 1) / 2f);
        using var fb = new SolidBrush(BarColor);
        g.FillPath(fb, fp);
    }

    protected override void Dispose(bool disposing) { if (disposing) _timer.Dispose(); base.Dispose(disposing); }
}

/// <summary>Строка итогов: части одного шрифта, каждая своим цветом, через «·».</summary>
internal sealed class CountsLine : Control
{
    private (string Text, Color Color)[] _parts = Array.Empty<(string, Color)>();

    public CountsLine()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        Font = Theme.BodyBold;
    }

    public void Set(params (string Text, Color Color)[] parts) { _parts = parts; Invalidate(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        int x = 0;
        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine;
        for (int i = 0; i < _parts.Length; i++)
        {
            if (i > 0)
            {
                const string sep = "   ·   ";
                TextRenderer.DrawText(g, sep, Font, new Rectangle(x, 0, Width - x, Height), Theme.Fg3, flags);
                x += TextRenderer.MeasureText(g, sep, Font, Size.Empty, flags).Width;
            }
            var (t, c) = _parts[i];
            TextRenderer.DrawText(g, t, Font, new Rectangle(x, 0, Width - x, Height), c, flags);
            x += TextRenderer.MeasureText(g, t, Font, Size.Empty, flags).Width;
        }
    }
}

/// <summary>Переключатель с подписью.</summary>
internal sealed class Toggle : Painted
{
    private bool _on;
    public event EventHandler? Changed;
    public bool On { get => _on; set { _on = value; Invalidate(); Changed?.Invoke(this, EventArgs.Empty); } }

    public Toggle() { Font = Theme.Body; Height = 24; }

    protected override void OnClick(EventArgs e) { if (Enabled) On = !On; base.OnClick(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        float k = K;
        var track = new RectangleF(0.5f, (Height - 17 * k) / 2, 34 * k, 17 * k);
        using (var p = Theme.Round(track, 8.5f * k))
        {
            using var b = new SolidBrush(_on ? (Enabled ? Theme.Accent : Theme.Fg3) : Theme.Bg3);
            g.FillPath(b, p);
            using var pen = new Pen(_on ? Color.Transparent : Hover ? Theme.Fg3 : Theme.Line);
            g.DrawPath(pen, p);
        }
        float kx = _on ? track.Right - 15 * k : track.X + 2 * k;
        using (var kb = new SolidBrush(_on ? Color.White : Theme.Fg2))
            g.FillEllipse(kb, kx, track.Y + 2 * k, 13 * k, 13 * k);
        int tx = (int)(44 * k);
        TextRenderer.DrawText(g, Text, Font, new Rectangle(tx, 0, Width - tx, Height), Enabled ? (Hover ? Theme.Fg : Theme.Fg2) : Theme.Fg3,
            TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPadding);
    }

    protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }
}
