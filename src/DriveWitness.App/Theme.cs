using System.Runtime.InteropServices;
using DriveWitness.Core;

namespace DriveWitness.App;

internal static class Theme
{
    internal static readonly Color Background = Color.FromArgb(10, 16, 25), Surface = Color.FromArgb(17, 26, 39), Border = Color.FromArgb(39, 55, 76),
        Text = Color.FromArgb(225, 234, 246), Muted = Color.FromArgb(151, 169, 192), Blue = Color.FromArgb(35, 126, 245), Cyan = Color.FromArgb(35, 186, 213);
    internal static readonly Font Font = new("Segoe UI", 9.5f), Heading = new("Segoe UI", 18, FontStyle.Bold);
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(nint window, int attribute, ref int value, int size);
    internal static void DarkTitle(Form window) { int enabled = 1; DwmSetWindowAttribute(window.Handle, 20, ref enabled, sizeof(int)); }
    internal static Label Label(string text, bool muted = false) => new() { Text = text, Dock = DockStyle.Fill, ForeColor = muted ? Muted : Text, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    internal static Button Button(string text, bool primary = false)
    {
        var b = new Button { Text = text, AutoSize = true, MinimumSize = new(65, 32), FlatStyle = FlatStyle.Flat, Padding = new(8, 3, 8, 3), BackColor = primary ? Blue : Surface, ForeColor = Text, Cursor = Cursors.Hand, AccessibleName = text };
        b.FlatAppearance.BorderColor = primary ? Blue : Border; b.FlatAppearance.MouseOverBackColor = Color.FromArgb(32, 61, 99); return b;
    }
    internal static FlowLayoutPanel Flow() => new() { Dock = DockStyle.Fill, WrapContents = false, Padding = new(0, 2, 0, 2), BackColor = Background };
    internal static Panel Card(Control child, int padding = 12)
    {
        var card = new Panel { Dock = DockStyle.Fill, BackColor = Surface, Padding = new(padding), Margin = new(0, 0, 10, 10) };
        child.Dock = DockStyle.Fill; card.Controls.Add(child); card.Paint += (_, e) => { using var pen = new Pen(Border); e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1); }; return card;
    }
    internal static DataGridView Table(bool virtualMode = false)
    {
        var table = new BufferedGrid { Dock = DockStyle.Fill, VirtualMode = virtualMode, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            AllowUserToOrderColumns = true, AllowUserToResizeRows = false, RowHeadersVisible = false, BackgroundColor = Surface, BorderStyle = BorderStyle.None,
            GridColor = Border, EnableHeadersVisualStyles = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = true,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None, ColumnHeadersHeight = 34, RowTemplate = { Height = 30 }, Font = Font,
            ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None, CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal,
            ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableWithoutHeaderText, AccessibleName = "Evidence records" };
        table.DefaultCellStyle = new() { BackColor = Surface, ForeColor = Text, SelectionBackColor = Color.FromArgb(23, 64, 112), SelectionForeColor = Text, Padding = new(6, 0, 6, 0) };
        table.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(14, 22, 34);
        table.ColumnHeadersDefaultCellStyle = new() { BackColor = Color.FromArgb(25, 37, 53), ForeColor = Text, SelectionBackColor = Surface, Font = new("Segoe UI", 9, FontStyle.Bold), Padding = new(6, 0, 6, 0) };
        return table;
    }
    internal static Color StatusColor(string? status) => status switch
    {
        "UNCHANGED" or "VERIFIED" or "COMPLETED" => Color.FromArgb(36, 192, 150), "ADDED" or "RENAMED" => Cyan,
        "MODIFIED" or "METADATA_CHANGED" or "UNSTABLE" or "UNVERIFIED" => Color.FromArgb(242, 184, 68),
        "ERROR" or "DELETED" or "FAILED" => Color.FromArgb(246, 101, 111), _ => Muted
    };
    internal static string Hash(byte[]? bytes, bool full = false)
    {
        if (bytes == null) return "—"; string value = Convert.ToHexStringLower(bytes); return full || value.Length <= 16 ? value : value[..10] + "…" + value[^4..];
    }
    internal static string Size(long? size) => size == null ? "—" : size < 1024 ? $"{size:N0} B" : size < 1048576 ? $"{size / 1024d:N1} KiB" : size < 1073741824 ? $"{size / 1048576d:N1} MiB" : $"{size / 1073741824d:N2} GiB";
    internal static string Time(long? ns) => ns == null ? "—" : EvidenceDatabase.Iso(ns.Value).Replace('T', ' ')[..19] + " UTC";
    internal static void Apply(Control control)
    {
        if (control is TextBox or ComboBox or CheckedListBox or TreeView or TrackBar or NumericUpDown) { control.BackColor = Surface; control.ForeColor = Text; }
        if (control is TextBox box) { box.BorderStyle = BorderStyle.FixedSingle; box.AccessibleName = box.PlaceholderText.Length > 0 ? box.PlaceholderText : "Input"; }
        if (control is ComboBox combo && combo.DrawMode != DrawMode.OwnerDrawFixed)
        {
            combo.DrawMode = DrawMode.OwnerDrawFixed;
            combo.DrawItem += (_, e) => { if (e.Index < 0) return; using var fill = new SolidBrush((e.State & DrawItemState.Selected) != 0 ? Color.FromArgb(23, 64, 112) : Surface); e.Graphics.FillRectangle(fill, e.Bounds); TextRenderer.DrawText(e.Graphics, combo.Items[e.Index]?.ToString(), combo.Font, e.Bounds, Text, TextFormatFlags.VerticalCenter | TextFormatFlags.Left); e.DrawFocusRectangle(); };
        }
        foreach (Control child in control.Controls) Apply(child);
    }
    private sealed class BufferedGrid : DataGridView { internal BufferedGrid() { DoubleBuffered = true; } }
}
