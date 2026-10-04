using System.Text.Json;
using DriveWitness.Core;

namespace DriveWitness.App;

internal sealed record ColumnState(string Name, int Width, int Order, bool Visible, bool Frozen);
internal sealed record WorkspaceState
{
    public int Width { get; init; } = 1400;
    public int Height { get; init; } = 900;
    public int? X { get; init; }
    public int? Y { get; init; }
    public string? Database { get; init; }
    public string[] RecentDatabases { get; init; } = [];
    public ColumnState[] Columns { get; init; } = [];
    public ColumnState[] HistoryColumns { get; init; } = [];
    public EvidenceQuery Filter { get; init; } = new();
    public int Performance { get; init; } = 60;
    public string Mode { get; init; } = "Verify";
    private static string StatePath => Path.Combine(Path.GetDirectoryName(ScanOptions.SettingsPath)!, "workspace.json");
    public static WorkspaceState Load()
    {
        try { return File.Exists(StatePath) ? JsonSerializer.Deserialize<WorkspaceState>(File.ReadAllText(StatePath), ScanOptions.Json) ?? new() : new(); }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return new(); }
    }
    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!); string temp = StatePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temp, JsonSerializer.Serialize(this, ScanOptions.Json)); File.Move(temp, StatePath, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    internal static ColumnState[] Capture(DataGridView table) => table.Columns.Cast<DataGridViewColumn>().Select(c => new ColumnState(c.Name, c.Width, c.DisplayIndex, c.Visible, c.Frozen)).ToArray();
    internal static void Restore(DataGridView table, ColumnState[] states)
    {
        foreach (var s in states.OrderBy(s => s.Order))
        {
            if (!table.Columns.Contains(s.Name)) continue; var c = table.Columns[s.Name]!; c.Width = Math.Clamp(s.Width, 40, 1500); c.Visible = s.Visible;
            c.DisplayIndex = Math.Clamp(s.Order, 0, table.Columns.Count - 1);
        }
        // Frozen columns must form a contiguous prefix in WinForms.
        foreach (var c in table.Columns.Cast<DataGridViewColumn>().OrderBy(c => c.DisplayIndex))
        { if (states.FirstOrDefault(s => s.Name == c.Name)?.Frozen != true) break; c.Frozen = true; }
    }
}
