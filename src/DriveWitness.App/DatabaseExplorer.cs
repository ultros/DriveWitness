using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;

namespace DriveWitness.App;

internal enum EvidenceActionKind { DatabaseReadOnly, LiveFilesystemReadOnly, Annotation, Export, Destructive }

internal sealed class DatabaseExplorer : UserControl
{
    private readonly TextBox search = new() { PlaceholderText = "Search path, filename, hash, file ID, scan ID…", Width = 320 };
    private readonly Label heading = Theme.Label("DATABASE EXPLORER"), metadata = Theme.Label("Open a DriveWitness database to review evidence.", true), footer = Theme.Label("No database open", true);
    private readonly TreeView tree = new() { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, HideSelection = false, ShowLines = false, ShowPlusMinus = true, ItemHeight = 27, Indent = 14 };
    private readonly DataGridView table = Theme.Table(true), versions = Theme.Table();
    private readonly TabControl inspector = new() { Dock = DockStyle.Fill, AccessibleName = "Selected file inspector", DrawMode = TabDrawMode.OwnerDrawFixed };
    private readonly Dictionary<string, TextBox> details = new();
    private readonly TextBox note = new() { Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical, PlaceholderText = "Analyst note · kept separate from evidence" };
    private readonly TextBox reviewSet = new() { Dock = DockStyle.Fill, PlaceholderText = "Review set, for example Known Good" };
    private readonly CheckBox flagged = new() { Text = "Flagged", AutoSize = true }, reviewed = new() { Text = "Reviewed", AutoSize = true };
    private readonly Button previous = Theme.Button("Previous"), next = Theme.Button("Next"), stop = Theme.Button("Cancel query"), saveNote = Theme.Button("Save review", true);
    private readonly System.Windows.Forms.Timer debounce = new() { Interval = 300 };
    private readonly Stack<QueryCursor?> cursors = new();
    private QueryCursor? cursor, versionCursor;
    private CancellationTokenSource? queryCancellation, selectionCancellation, operationCancellation;
    private DatabaseQueryService? service;
    private IReadOnlyList<FileRecord> rows = [];
    private FileRecord? selected;
    private int generation, selectionGeneration;
    private bool loading, selectionReady;
    private EvidenceQuery query = new();
    private IReadOnlyList<ScanEntry> scans = [];
    internal event Action<string>? DatabaseOpened;
    internal string? DatabasePath => service?.Database;
    internal EvidenceQuery Query => query;
    internal ColumnState[] Columns => WorkspaceState.Capture(table);
    internal int VisibleRecordCount => rows.Count;
    internal void RestoreColumns(ColumnState[] columns) => WorkspaceState.Restore(table, columns);

    internal DatabaseExplorer(ColumnState[] columns)
    {
        Dock = DockStyle.Fill; BackColor = Theme.Background; ForeColor = Theme.Text; Font = Theme.Font;
        ((Theme.BufferedGrid)table).EvidenceClipboardContent = () => new DataObject(DataFormats.UnicodeText, SelectedCellText());
        inspector.DrawItem += (_, e) => { using var fill = new SolidBrush(e.Index == inspector.SelectedIndex ? Color.FromArgb(23, 64, 112) : Theme.Surface); e.Graphics.FillRectangle(fill, e.Bounds); TextRenderer.DrawText(e.Graphics, inspector.TabPages[e.Index].Text, Font, e.Bounds, Theme.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter); };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new(0) };
        foreach (var h in new[] { 52, 44, 0, 48 }) layout.RowStyles.Add(h == 0 ? new(SizeType.Percent, 100) : new(SizeType.Absolute, h)); Controls.Add(layout);
        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 }; heading.Font = new("Segoe UI", 13, FontStyle.Bold); header.Controls.Add(heading); header.Controls.Add(metadata); layout.Controls.Add(header, 0, 0);
        header.RowStyles.Add(new(SizeType.Percent, 50)); header.RowStyles.Add(new(SizeType.Percent, 50));
        var toolbar = Theme.Flow(); var open = Theme.Button("Open database"); var filters = Theme.Button("Filters"); var changed = Theme.Button("Changed only"); var errors = Theme.Button("Errors"); var columnsButton = Theme.Button("Columns"); var export = Theme.Button("Export");
        toolbar.Controls.AddRange([search, filters, changed, errors, columnsButton, export, open]); layout.Controls.Add(toolbar, 0, 1);
        var panes = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1 }; panes.ColumnStyles.Add(new(SizeType.Absolute, 180)); panes.ColumnStyles.Add(new(SizeType.Percent, 100)); panes.ColumnStyles.Add(new(SizeType.Absolute, 325));
        panes.RowStyles.Add(new(SizeType.Percent, 100));
        panes.Controls.Add(Theme.Card(tree, 8), 0, 0); panes.Controls.Add(Theme.Card(table, 0), 1, 0); panes.Controls.Add(Theme.Card(inspector, 8), 2, 0); layout.Controls.Add(panes, 0, 2);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 }; bottom.ColumnStyles.Add(new(SizeType.Percent, 100)); bottom.ColumnStyles.Add(new(SizeType.Absolute, 290)); bottom.Controls.Add(footer, 0, 0);
        bottom.RowCount = 1; bottom.RowStyles.Add(new(SizeType.Percent, 100));
        var paging = Theme.Flow(); paging.Controls.AddRange([previous, next, stop]); bottom.Controls.Add(paging, 1, 0); layout.Controls.Add(bottom, 0, 3);
        foreach (var spec in new (string Name, string Caption, int Width)[] { ("status", "Status", 130), ("filename", "Filename", 170), ("path", "Path", 330), ("size", "Size", 90), ("extension", "Extension", 80), ("modified", "Modified UTC", 180), ("created", "Created UTC", 180), ("blake3", "BLAKE3", 160), ("sha256", "SHA-256", 160), ("verification", "Verification", 170), ("file_id", "File ID", 200), ("scan", "Scan", 70), ("error", "Error", 220), ("accessed", "Accessed UTC", 180), ("attributes", "Attributes", 100), ("volume", "Volume ID", 130), ("first_seen", "First seen scan", 110), ("last_seen", "Last seen scan", 110), ("sha_origin", "SHA-256 source scan", 130), ("sha_provenance", "Hash source", 160), ("legacy", "Legacy SHA-1", 220) })
        { var c = new DataGridViewTextBoxColumn { Name = spec.Name, HeaderText = spec.Caption, Width = spec.Width, SortMode = DataGridViewColumnSortMode.Programmatic }; c.Visible = table.Columns.Count < 13; if (spec.Name is "blake3" or "sha256" or "file_id" or "legacy") c.DefaultCellStyle.Font = new("Consolas", 9); table.Columns.Add(c); }
        WorkspaceState.Restore(table, columns);
        foreach (var tab in new[] { "Summary", "Hashes", "Timeline", "Versions", "Metadata", "Errors", "Notes" })
        {
            var page = new TabPage(tab) { BackColor = Theme.Surface, ForeColor = Theme.Text, Padding = new(8) }; inspector.TabPages.Add(page);
            if (tab == "Versions")
            {
                var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 }; panel.RowStyles.Add(new(SizeType.Percent, 100)); panel.RowStyles.Add(new(SizeType.Absolute, 40));
                versions.Columns.Add("scan", "Scan"); versions.Columns.Add("path", "Path"); versions.Columns.Add("size", "Size"); versions.Columns.Add("b3", "BLAKE3"); versions.Columns.Add("sha", "SHA-256"); versions.Columns.Add("status", "Status"); versions.Columns.Add("method", "Verification");
                panel.Controls.Add(versions, 0, 0); var actions = Theme.Flow(); var diff = Theme.Button("Compare 2 versions"); var more = Theme.Button("More history"); actions.Controls.AddRange([diff, more]); panel.Controls.Add(actions, 0, 1); page.Controls.Add(panel);
                diff.Click += (_, _) => { var picked = versions.SelectedRows.Cast<DataGridViewRow>().Select(r => (FileRecord)r.Tag!).OrderBy(r => r.ScanId).ToArray(); if (picked.Length == 2) ShowDifferences("Version comparison", picked[0], picked[1]); else footer.Text = "Select exactly two historical versions to compare."; };
                more.Click += async (_, _) => { if (selected != null && versionCursor != null) await LoadVersions(selected, true); };
            }
            else if (tab == "Notes")
            {
                var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 4 }; panel.RowStyles.Add(new(SizeType.Absolute, 36)); panel.RowStyles.Add(new(SizeType.Absolute, 36)); panel.RowStyles.Add(new(SizeType.Percent, 100)); panel.RowStyles.Add(new(SizeType.Absolute, 42));
                var flags = Theme.Flow(); flags.Controls.AddRange([flagged, reviewed]); panel.Controls.Add(flags, 0, 0); panel.Controls.Add(reviewSet, 0, 1); panel.Controls.Add(note, 0, 2); panel.Controls.Add(saveNote, 0, 3); page.Controls.Add(panel);
            }
            else { var box = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true, BorderStyle = BorderStyle.None, Text = "Select an evidence record." }; if (tab == "Hashes") box.Font = new("Consolas", 9); details[tab] = box; page.Controls.Add(box); }
        }
        open.Click += async (_, _) => await ChooseDatabase(); search.TextChanged += (_, _) => { debounce.Stop(); debounce.Start(); };
        debounce.Tick += async (_, _) => { debounce.Stop(); query = query with { Search = search.Text.Trim() }; await RefreshQuery(); };
        changed.Click += async (_, _) => { query = query with { ChangedOnly = !query.ChangedOnly, Status = null }; await RefreshQuery(); };
        errors.Click += async (_, _) => { query = query with { Status = "ERROR", ChangedOnly = false }; await RefreshQuery(); };
        filters.Click += (_, _) => AdvancedFilters(); columnsButton.Click += (_, _) => ShowColumns(); export.Click += async (_, _) => await Export(false);
        previous.Click += async (_, _) => { if (cursors.Count > 0) { cursor = cursors.Pop(); await Fetch(); } };
        next.Click += async (_, _) => { if (lastPage?.HasMore == true) { cursors.Push(cursor); cursor = lastPage.Next; await Fetch(); } };
        stop.Click += (_, _) => { queryCancellation?.Cancel(); selectionCancellation?.Cancel(); operationCancellation?.Cancel(); };
        tree.AfterSelect += async (_, e) => { if (!loading && e.Node?.Tag is EvidenceQuery filter) { bool scan = e.Node.Parent?.Text == "SCANS (latest 500)"; query = filter with { Search = search.Text.Trim(), ScanId = scan ? filter.ScanId : query.ScanId, BaselineScanId = scan ? null : query.BaselineScanId }; await RefreshQuery(); } };
        table.CellValueNeeded += (_, e) => { if (e.RowIndex >= 0 && e.RowIndex < rows.Count) e.Value = Value(rows[e.RowIndex], table.Columns[e.ColumnIndex].Name); };
        table.CellFormatting += (_, e) => { if (e.ColumnIndex == 0 && e.RowIndex >= 0 && e.RowIndex < rows.Count && e.CellStyle != null) e.CellStyle.ForeColor = Theme.StatusColor(rows[e.RowIndex].Status); };
        table.CellToolTipTextNeeded += (_, e) => { if (e.RowIndex >= 0 && e.RowIndex < rows.Count) e.ToolTipText = Value(rows[e.RowIndex], table.Columns[e.ColumnIndex].Name, true)?.ToString(); };
        table.SelectionChanged += async (_, _) => await SelectRecord();
        table.ColumnHeaderMouseClick += async (_, e) => { string col = table.Columns[e.ColumnIndex].Name; if (new[] { "path", "size", "modified", "created", "status", "verification", "scan" }.Contains(col)) { query = query with { Sort = col, Descending = query.Sort == col && !query.Descending }; await RefreshQuery(); } };
        table.CellMouseDown += (_, e) => { if (e.Button == MouseButtons.Right && e.RowIndex >= 0) { if (!table.Rows[e.RowIndex].Selected) { table.ClearSelection(); table.Rows[e.RowIndex].Selected = true; } table.CurrentCell = table.Rows[e.RowIndex].Cells[Math.Max(0, e.ColumnIndex)]; } };
        var menu = new ContextMenuStrip { BackColor = Theme.Surface, ForeColor = Theme.Text }; table.ContextMenuStrip = menu; menu.Opening += (_, e) => { if (CurrentRecord() is not FileRecord row) { e.Cancel = true; return; } PopulateMenu(menu, row); };
        saveNote.Click += async (_, _) => await SaveReview();
        Theme.Apply(this); previous.Enabled = next.Enabled = stop.Enabled = saveNote.Enabled = false;
    }
    private EvidencePage? lastPage;
    internal async Task ChooseDatabase()
    {
        using var dialog = new OpenFileDialog { Title = "Open DriveWitness evidence", Filter = "Evidence databases|*.db;*.sqlite;*.sqlite3|All files|*.*" };
        if (dialog.ShowDialog(this) == DialogResult.OK) await OpenDatabase(dialog.FileName);
    }
    internal async Task OpenDatabase(string path, EvidenceQuery? initial = null)
    {
        queryCancellation?.Cancel(); selectionCancellation?.Cancel(); generation++; service = new(path); query = initial ?? new(); search.Text = query.Search; debounce.Stop();
        heading.Text = Path.GetFileName(path); metadata.Text = "Reading scan catalog…"; DatabaseOpened?.Invoke(service.Database);
        try
        {
            var local = service; int id = generation; var loaded = await Task.Run(() => local.GetScans()); if (IsDisposed || id != generation) return; scans = loaded;
            if (initial == null && scans.Count > 0) query = query with { ScanId = scans[0].Id };
            BuildTree(); metadata.Text = $"{scans.Count:N0} scans shown · evidence read-only · 256 records per window · health check on demand";
            await RefreshQuery();
        }
        catch (Exception ex) { footer.Text = "Database unavailable: " + ex.Message; }
    }
    private void BuildTree()
    {
        loading = true; tree.BeginUpdate(); tree.Nodes.Clear();
        var databaseNode = tree.Nodes.Add("DATABASE"); databaseNode.Nodes.Add(Path.GetFileName(service?.Database));
        var scanNode = tree.Nodes.Add("SCANS (latest 500)"); scanNode.Nodes.Add(new TreeNode("All observations") { Tag = new EvidenceQuery() });
        foreach (var s in scans) scanNode.Nodes.Add(new TreeNode($"#{s.Id}  {s.Started.Replace('T', ' ')[..Math.Min(16, s.Started.Length)]}  {s.Mode}") { Tag = new EvidenceQuery { ScanId = s.Id } });
        var statusNode = tree.Nodes.Add("STATUS"); foreach (string status in new[] { "UNCHANGED", "MODIFIED", "ADDED", "DELETED", "RENAMED", "METADATA_CHANGED", "UNVERIFIED", "UNSTABLE", "ERROR", "LEGACY" }) statusNode.Nodes.Add(new TreeNode(status.Replace('_', ' ')) { Tag = new EvidenceQuery { ScanId = query.ScanId, Status = status } });
        var methodNode = tree.Nodes.Add("VERIFICATION"); foreach (string method in new[] { "FULL_DUAL_HASH", "FULL_BLAKE3", "USN_INCREMENTAL", "CARRIED_FORWARD", "LEGACY" }) methodNode.Nodes.Add(new TreeNode(method.Replace('_', ' ')) { Tag = new EvidenceQuery { ScanId = query.ScanId, Method = method } });
        var saved = tree.Nodes.Add("SAVED VIEWS"); saved.Nodes.Add(new TreeNode("Changed files") { Tag = new EvidenceQuery { ScanId = query.ScanId, ChangedOnly = true } });
        saved.Nodes.Add(new TreeNode("Large files (>100 MiB)") { Tag = new EvidenceQuery { ScanId = query.ScanId, MinimumSize = 100 * 1048576 } });
        saved.Nodes.Add(new TreeNode("Duplicates (BLAKE3)") { Tag = new EvidenceQuery { ScanId = query.ScanId, Duplicates = true } });
        saved.Nodes.Add(new TreeNode("Recently modified (7 days)") { Tag = new EvidenceQuery { ScanId = query.ScanId, ModifiedAfterNs = (DateTime.UtcNow.AddDays(-7).Ticks - DateTime.UnixEpoch.Ticks) * 100 } });
        foreach (string review in new[] { "flagged", "reviewed", "unreviewed" }) saved.Nodes.Add(new TreeNode(char.ToUpperInvariant(review[0]) + review[1..]) { Tag = new EvidenceQuery { ScanId = query.ScanId, Review = review } });
        databaseNode.Expand(); scanNode.Expand(); statusNode.Expand(); saved.Expand(); tree.EndUpdate(); loading = false;
    }
    internal async Task ApplyQuery(EvidenceQuery filter) { query = filter; search.Text = query.Search; debounce.Stop(); await RefreshQuery(); }
    internal void FocusSearch() => search.Focus();
    internal async Task RefreshQuery() { cursor = null; cursors.Clear(); await Fetch(); }
    private async Task Fetch()
    {
        if (service == null) return; queryCancellation?.Cancel(); queryCancellation?.Dispose(); queryCancellation = new(); var token = queryCancellation.Token;
        selectionCancellation?.Cancel(); int id = ++generation; var local = service; var filter = query; var after = cursor;
        stop.Enabled = true; previous.Enabled = next.Enabled = false; footer.Text = "Querying evidence…";
        rows = []; selected = null; table.RowCount = 0; ClearInspector();
        var time = Stopwatch.StartNew();
        try
        {
            var page = await Task.Run(() => local.SearchFiles(filter, after, token: token), token); if (IsDisposed || id != generation || token.IsCancellationRequested) return;
            rows = page.Rows; lastPage = page; table.RowCount = rows.Count;
            metadata.Text = $"{(query.ScanId == null ? "All scans" : "Scan #" + query.ScanId)}{(query.BaselineScanId == null ? "" : " · compared with #" + query.BaselineScanId)} · {scans.Count} scans shown · evidence read-only · 256 records per window";
            foreach (DataGridViewColumn col in table.Columns) col.HeaderCell.SortGlyphDirection = col.Name == query.Sort ? query.Descending ? SortOrder.Descending : SortOrder.Ascending : SortOrder.None;
            footer.Text = rows.Count == 0 ? "No records match these filters. Use SCANS → All observations to reset." : $"Window {cursors.Count + 1:N0} · {rows.Count:N0} records · query {time.Elapsed.TotalMilliseconds:N0} ms · {(page.HasMore ? "more available" : "end of results")}";
            previous.Enabled = cursors.Count > 0; next.Enabled = page.HasMore;
        }
        catch (Exception ex) { if (!IsDisposed && id == generation) footer.Text = token.IsCancellationRequested ? "Query cancelled." : "Query failed: " + ex.Message; }
        finally { if (!IsDisposed && id == generation) stop.Enabled = false; }
    }
    private static object? Value(FileRecord r, string name, bool full = false) => name switch
    {
        "status" => r.Status, "filename" => Path.GetFileName(r.CanonicalPath), "path" => r.CanonicalPath, "size" => full ? r.Size : Theme.Size(r.Size),
        "extension" => Path.GetExtension(r.CanonicalPath), "modified" => Theme.Time(r.ModifiedNs), "created" => Theme.Time(r.CreatedNs), "accessed" => Theme.Time(r.AccessedNs),
        "blake3" => Theme.Hash(r.Blake3, full), "sha256" => Theme.Hash(r.Sha256, full), "verification" => r.Method, "file_id" => r.FileId,
        "scan" => r.ScanId, "error" => r.ErrorCode == null ? "—" : r.ErrorCode + ": " + r.ErrorMessage, "attributes" => r.Attributes,
        "volume" => r.VolumeSerial, "first_seen" => r.FirstSeenScan, "last_seen" => r.LastSeenScan, "sha_origin" => r.Sha256OriginScan, "sha_provenance" => r.Sha256Provenance, "legacy" => r.LegacySha1, _ => "—"
    };
    private FileRecord? CurrentRecord() => table.CurrentCell is { RowIndex: >= 0 } cell && cell.RowIndex < rows.Count ? rows[cell.RowIndex] : null;
    private void ClearInspector()
    {
        selectionGeneration++; selectionReady = false; saveNote.Enabled = false; versions.Rows.Clear(); versionCursor = null;
        foreach (var box in details.Values) box.Text = "Select an evidence record."; note.Clear(); reviewSet.Clear(); flagged.Checked = reviewed.Checked = false;
    }
    private async Task SelectRecord()
    {
        var row = CurrentRecord(); if (row == null || row == selected || service == null) return; selected = row; ClearInspector();
        selectionCancellation?.Cancel(); selectionCancellation?.Dispose(); selectionCancellation = new(); int id = selectionGeneration; var token = selectionCancellation.Token;
        details["Summary"].Text = $"{Path.GetFileName(row.CanonicalPath)}\r\n\r\n{row.CanonicalPath}\r\n\r\nSTATUS\r\n{row.Status}\r\n\r\nVERIFICATION\r\n{row.Method}\r\n\r\nSIZE\r\n{Theme.Size(row.Size)} ({row.Size:N0} bytes)\r\n\r\nSCAN\r\n{row.ScanId}\r\n\r\nVOLUME\r\n{row.VolumeSerial ?? "Unavailable"}\r\n\r\nFILE ID\r\n{row.FileId ?? "Unavailable"}\r\n\r\nCanonical paths are stored observations. Live reads can affect access times.";
        string observationTime;
        try { observationTime = EvidenceDatabase.Decompress(row.ScanTime) ?? "Unavailable"; } catch (Exception ex) when (ex is IOException or System.Text.DecoderFallbackException) { observationTime = "Invalid compressed display field"; }
        details["Hashes"].Text = $"BLAKE3\r\n{Theme.Hash(row.Blake3, true)}\r\n\r\nObservation scan: {row.ScanId}\r\nMethod: {row.Method}\r\n\r\nSHA-256\r\n{Theme.Hash(row.Sha256, true)}\r\n\r\nOrigin scan: {row.Sha256OriginScan}\r\nProvenance: {row.Sha256Provenance}\r\nCarried forward: {(row.Sha256Provenance == "CARRIED_FORWARD" ? "Yes" : "No")}\r\n\r\nLegacy SHA-1\r\n{row.LegacySha1 ?? "Unavailable"}\r\n\r\nBackend: CPU for C# collections; historical backend not separately recorded.\r\nObservation time: {observationTime}";
        details["Metadata"].Text = $"CREATED\r\n{Theme.Time(row.CreatedNs)}\r\n\r\nMODIFIED\r\n{Theme.Time(row.ModifiedNs)}\r\n\r\nACCESSED\r\n{Theme.Time(row.AccessedNs)}\r\n\r\nATTRIBUTES\r\n{row.Attributes}\r\n\r\nHARD LINKS\r\n{row.HardlinkCount}\r\n\r\nFIRST SEEN SCAN\r\n{row.FirstSeenScan}\r\n\r\nLAST SEEN SCAN\r\n{row.LastSeenScan}";
        details["Errors"].Text = row.ErrorCode == null ? "No error is recorded for this observation." : row.ErrorCode + "\r\n\r\n" + row.ErrorMessage;
        try
        {
            string db = service.Database; var review = await Task.Run(() => new ReviewStore(db).Get(row), token);
            if (IsDisposed || token.IsCancellationRequested || id != selectionGeneration) return;
            flagged.Checked = review?.Flagged ?? false; reviewed.Checked = review?.Reviewed ?? false; note.Text = review?.Note ?? ""; reviewSet.Text = review?.Set ?? ""; selectionReady = true; saveNote.Enabled = true;
            await LoadVersions(row, false);
        }
        catch (Exception ex) { if (!IsDisposed && id == selectionGeneration) footer.Text = token.IsCancellationRequested ? "Selection cancelled" : ex.Message; }
    }
    private async Task LoadVersions(FileRecord row, bool more)
    {
        if (service == null || selectionCancellation == null) return; var local = service; int id = selectionGeneration; var token = selectionCancellation.Token; var after = more ? versionCursor : null;
        var page = await Task.Run(() => local.GetFileVersions(row, after, token), token);
        if (IsDisposed || id != selectionGeneration || token.IsCancellationRequested) return;
        versions.Rows.Clear(); foreach (var r in page.Rows) { int index = versions.Rows.Add(r.ScanId, r.CanonicalPath, Theme.Size(r.Size), Theme.Hash(r.Blake3), Theme.Hash(r.Sha256), r.Status ?? "—", r.Method ?? "—"); versions.Rows[index].Tag = r; }
        versionCursor = page.HasMore ? page.Next : null;
        details["Timeline"].Text = $"OBSERVATION HISTORY\r\n{page.Rows.Count} observations in this window{(page.HasMore ? " · more in Versions" : "")}\r\n\r\n" + string.Join("\r\n\r\n", page.Rows.Reverse().Select(r => $"Scan #{r.ScanId} · {scans.FirstOrDefault(s => s.Id == r.ScanId)?.Started ?? "date unavailable"}\r\n{r.Status} · {r.Method}\r\n{r.CanonicalPath}\r\nModified: {Theme.Time(r.ModifiedNs)}\r\nBLAKE3: {Theme.Hash(r.Blake3)}"));
    }
    private async Task SaveReview()
    {
        if (selected == null || service == null || !selectionReady) return; var row = selected; string db = service.Database, text = note.Text, set = reviewSet.Text; bool flag = flagged.Checked, review = reviewed.Checked; saveNote.Enabled = false;
        try { await Task.Run(() => new ReviewStore(db).Save(row, flag, review, text, set)); if (!IsDisposed) footer.Text = "Review saved to a separate annotation database. Evidence roots are unchanged."; }
        catch (Exception ex) { if (!IsDisposed) footer.Text = "Review error: " + ex.Message; }
        finally { if (!IsDisposed && row == selected) saveNote.Enabled = true; }
    }
    internal void CopyRecord() { if (CurrentRecord() is FileRecord row) Clipboard.SetText(JsonSerializer.Serialize(DatabaseQueryService.DisplayRecord(row), ScanOptions.Json)); }
    internal void CopyCells()
    {
        string text = SelectedCellText(); if (text.Length > 0) Clipboard.SetText(text);
    }
    private string SelectedCellText()
    {
        var cells = table.SelectedCells.Cast<DataGridViewCell>().Where(c => c.RowIndex < rows.Count).OrderBy(c => c.RowIndex).ThenBy(c => c.ColumnIndex).GroupBy(c => c.RowIndex);
        return string.Join(Environment.NewLine, cells.Select(group => string.Join('\t', group.Select(c => Value(rows[c.RowIndex], table.Columns[c.ColumnIndex].Name, true)))));
    }
    internal bool NativeCopyContainsFullDigests()
    {
        if (CurrentRecord() is not FileRecord { Blake3: not null, Sha256: not null } row) return false;
        string text = table.GetClipboardContent()?.GetText(TextDataFormat.UnicodeText) ?? "";
        return text.Contains(Convert.ToHexStringLower(row.Blake3), StringComparison.Ordinal) && text.Contains(Convert.ToHexStringLower(row.Sha256), StringComparison.Ordinal);
    }
    private void PopulateMenu(ContextMenuStrip menu, FileRecord row)
    {
        menu.Items.Clear();
        ToolStripMenuItem Group(string caption) { var group = new ToolStripMenuItem(caption); menu.Items.Add(group); return group; }
        void Add(ToolStripMenuItem group, string caption, EvidenceActionKind kind, Action action, bool enabled = true)
        { var item = new ToolStripMenuItem(caption) { Enabled = enabled, Tag = kind }; item.Click += (_, _) => action(); group.DropDownItems.Add(item); }
        var open = Group("Open"); Add(open, "Details", EvidenceActionKind.DatabaseReadOnly, () => inspector.SelectedIndex = 0); Add(open, "Timeline", EvidenceActionKind.DatabaseReadOnly, () => inspector.SelectedIndex = 2); Add(open, "Version history", EvidenceActionKind.DatabaseReadOnly, () => inspector.SelectedIndex = 3);
        var compare = Group("Compare"); Add(compare, "With previous version", EvidenceActionKind.DatabaseReadOnly, async () => await ComparePrevious(row)); Add(compare, "Against current disk", EvidenceActionKind.LiveFilesystemReadOnly, async () => await LiveCompare(row, false), row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal)); Add(compare, "With another version / scan", EvidenceActionKind.DatabaseReadOnly, () => inspector.SelectedIndex = 3);
        var copy = Group("Copy"); foreach (var field in new[] { ("Filename", Path.GetFileName(row.CanonicalPath)), ("Full path", row.CanonicalPath), ("BLAKE3", row.Blake3 == null ? null : Theme.Hash(row.Blake3, true)), ("SHA-256", row.Sha256 == null ? null : Theme.Hash(row.Sha256, true)), ("File ID", row.FileId) }) Add(copy, field.Item1, EvidenceActionKind.DatabaseReadOnly, () => Clipboard.SetText(field.Item2!), field.Item2 != null);
        Add(copy, "Full record", EvidenceActionKind.DatabaseReadOnly, CopyRecord); Add(copy, "Selected cells", EvidenceActionKind.DatabaseReadOnly, CopyCells);
        var investigate = Group("Investigate"); Add(investigate, "Same BLAKE3", EvidenceActionKind.DatabaseReadOnly, async () => await ApplyQuery(new() { Blake3 = Theme.Hash(row.Blake3, true) }), row.Blake3 != null); Add(investigate, "Same SHA-256", EvidenceActionKind.DatabaseReadOnly, async () => await ApplyQuery(new() { Sha256 = Theme.Hash(row.Sha256, true) }), row.Sha256 != null);
        Add(investigate, "Same file ID / other paths", EvidenceActionKind.DatabaseReadOnly, async () => await ApplyQuery(new() { FileId = row.FileId, VolumeSerial = row.VolumeSerial }), row.FileId != null && row.VolumeSerial != null);
        Add(investigate, "Find duplicates", EvidenceActionKind.DatabaseReadOnly, async () => await ApplyQuery(new() { ScanId = row.ScanId, Duplicates = true }), row.Blake3 != null); Add(investigate, "All historical versions", EvidenceActionKind.DatabaseReadOnly, () => inspector.SelectedIndex = 3);
        var verify = Group("Verify"); Add(verify, "Verify file now (BLAKE3 + changed SHA-256)", EvidenceActionKind.LiveFilesystemReadOnly, async () => await LiveCompare(row, false), row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal)); Add(verify, "Full dual rehash", EvidenceActionKind.LiveFilesystemReadOnly, async () => await LiveCompare(row, true), row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal));
        var filesystem = Group("Filesystem"); Add(filesystem, "Open file location", EvidenceActionKind.LiveFilesystemReadOnly, async () => await Reveal(row, true), row.Status != "DELETED"); Add(filesystem, "Open containing folder", EvidenceActionKind.LiveFilesystemReadOnly, async () => await Reveal(row, false), !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal));
        Add(filesystem, "Properties", EvidenceActionKind.LiveFilesystemReadOnly, async () =>
        {
            try { string? path = await Task.Run(() => LiveFileComparison.DiskPath(row)); if (path != null && await Task.Run(() => File.Exists(path))) WindowsFileActions.Properties(path, Handle); else footer.Text = "Historical file is not currently available."; }
            catch (Exception ex) { footer.Text = ex.Message; }
        }, row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal));
        var review = Group("Review"); Add(review, "Flag / mark reviewed / add note / review set", EvidenceActionKind.Annotation, () => inspector.SelectedIndex = 6);
        var export = Group("Export"); Add(export, "Selected record", EvidenceActionKind.Export, async () => await Export(true, [row])); Add(export, "Selected rows", EvidenceActionKind.Export, async () => await Export(true)); Add(export, "Evidence report (HTML)", EvidenceActionKind.Export, async () => await Export(true, null, "html"));
    }
    private async Task ComparePrevious(FileRecord row)
    {
        if (service == null) return;
        try { var local = service; var older = await Task.Run(() => local.GetPreviousVersion(row)); if (older == null) footer.Text = "No earlier observation is recorded for this file identity."; else ShowDifferences("Previous observation", older, row); }
        catch (Exception ex) { footer.Text = ex.Message; }
    }
    private async Task LiveCompare(FileRecord row, bool dual)
    {
        if (service == null || operationCancellation != null) return; string db = service.Database; operationCancellation = new(); var control = new ScanControl(); using var cancel = operationCancellation.Token.Register(control.Cancel); stop.Enabled = true; footer.Text = "Reading current file…";
        try
        {
            var result = await Task.Run(() => LiveFileComparison.Compare(row, dual, control)); if (IsDisposed) return;
            if (result.Current == null) { ShowText(result.Result, result.Error ?? result.Result); return; }
            ShowDifferences(result.Result, row, result.Current);
            using var dialog = new Form { Text = "Save verification event", ClientSize = new(560, 120), StartPosition = FormStartPosition.CenterParent, BackColor = Theme.Background, ForeColor = Theme.Text, Font = Theme.Font };
            var body = Theme.Label($"{result.Result} · observed {result.ObservedUtc}\nStore this result in the separate review database?"); body.Dock = DockStyle.Fill; dialog.Controls.Add(body); var save = Theme.Button("Save new verification event"); save.Dock = DockStyle.Bottom; dialog.Controls.Add(save); bool persist = false; save.Click += (_, _) => { persist = true; dialog.Close(); }; dialog.ShowDialog(this);
            if (persist) await Task.Run(() => new ReviewStore(db).AppendVerification(row, result)); footer.Text = result.Result + (persist ? " · new verification event saved" : " · historical evidence unchanged");
        }
        catch (Exception ex) { if (!IsDisposed) footer.Text = "Live verification: " + ex.Message; }
        finally { operationCancellation?.Dispose(); operationCancellation = null; if (!IsDisposed) stop.Enabled = false; }
    }
    private async Task Reveal(FileRecord row, bool select)
    {
        try
        {
            string? path = await Task.Run(() => LiveFileComparison.DiskPath(row)); if (path == null) { footer.Text = "Anonymized path is unavailable."; return; }
            bool exists = await Task.Run(() => select ? File.Exists(path) : Directory.Exists(Path.GetDirectoryName(path)));
            if (!exists) { footer.Text = "This historical location is not currently available."; return; }
            var start = new ProcessStartInfo("explorer.exe") { UseShellExecute = true }; if (select) start.ArgumentList.Add("/select," + path); else start.ArgumentList.Add(Path.GetDirectoryName(path)!); Process.Start(start)?.Dispose();
        }
        catch (Exception ex) { footer.Text = ex.Message; }
    }
    internal async Task Export(bool selection, IReadOnlyList<FileRecord>? explicitRows = null, string? forcedFormat = null)
    {
        if (service == null || operationCancellation != null) return;
        using var dialog = new SaveFileDialog { Title = "Export evidence with provenance", Filter = "JSON|*.json|CSV|*.csv|JSON lines|*.jsonl|HTML report|*.html", FileName = forcedFormat == "html" ? "evidence-report.html" : "evidence.json", FilterIndex = forcedFormat == "html" ? 4 : 1 };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string format = forcedFormat ?? new[] { "json", "csv", "jsonl", "html" }[dialog.FilterIndex - 1]; var picked = explicitRows ?? (selection ? table.SelectedRows.Cast<DataGridViewRow>().Where(r => r.Index < rows.Count).Select(r => rows[r.Index]).ToArray() : null);
        var local = service; var filter = query; string output = dialog.FileName; operationCancellation = new(); var token = operationCancellation.Token; stop.Enabled = true; footer.Text = "Streaming evidence export…";
        try { await Task.Run(() => local.Export(filter, output, format, token, picked), token); if (!IsDisposed) footer.Text = "Exported " + output; }
        catch (Exception ex) { if (!IsDisposed) footer.Text = token.IsCancellationRequested ? "Export cancelled; output was not replaced." : ex.Message; }
        finally { operationCancellation.Dispose(); operationCancellation = null; if (!IsDisposed) stop.Enabled = false; }
    }
    private void ShowColumns()
    {
        var menu = new ContextMenuStrip { BackColor = Theme.Surface, ForeColor = Theme.Text };
        foreach (DataGridViewColumn column in table.Columns)
        {
            var item = new ToolStripMenuItem(column.HeaderText) { Checked = column.Visible, CheckOnClick = true }; item.Click += (_, _) => column.Visible = item.Checked; menu.Items.Add(item);
        }
        menu.Items.Add(new ToolStripSeparator()); var pin = new ToolStripMenuItem("Pin status + filename"); pin.Click += (_, _) => { foreach (DataGridViewColumn c in table.Columns) c.Frozen = false; table.Columns[0].DisplayIndex = 0; table.Columns[1].DisplayIndex = 1; table.Columns[0].Frozen = table.Columns[1].Frozen = true; }; menu.Items.Add(pin);
        var unpin = new ToolStripMenuItem("Unpin columns"); unpin.Click += (_, _) => { foreach (DataGridViewColumn c in table.Columns) c.Frozen = false; }; menu.Items.Add(unpin); menu.Closed += (_, _) => menu.Dispose(); menu.Show(Cursor.Position);
    }
    private void AdvancedFilters()
    {
        using var dialog = new Form { Text = "Evidence filters", ClientSize = new(520, 400), StartPosition = FormStartPosition.CenterParent, Font = Theme.Font, BackColor = Theme.Background, ForeColor = Theme.Text };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(20) }; layout.ColumnStyles.Add(new(SizeType.Absolute, 160)); layout.ColumnStyles.Add(new(SizeType.Percent, 100)); dialog.Controls.Add(layout); int i = 0;
        TextBox Field(string text, string value) { var box = new TextBox { Dock = DockStyle.Fill, Text = value }; layout.RowStyles.Add(new(SizeType.Absolute, 40)); layout.Controls.Add(Theme.Label(text), 0, i); layout.Controls.Add(box, 1, i++); return box; }
        var path = Field("Path contains", query.PathContains ?? ""); var ext = Field("Extension", query.Extension ?? ""); var min = Field("Minimum bytes", query.MinimumSize?.ToString() ?? ""); var max = Field("Maximum bytes", query.MaximumSize?.ToString() ?? ""); var date = Field("Modified after UTC", query.ModifiedAfterNs == null ? "" : EvidenceDatabase.Iso(query.ModifiedAfterNs.Value)); var hash = Field("BLAKE3 prefix", query.Blake3 ?? ""); var set = Field("Review set", query.ReviewSet ?? "");
        var apply = Theme.Button("Apply filters", true); var reset = Theme.Button("Reset filters"); layout.Controls.Add(reset, 0, i); layout.Controls.Add(apply, 1, i); Theme.Apply(dialog);
        apply.Click += async (_, _) =>
        {
            try
            {
                long? Number(string text) => string.IsNullOrWhiteSpace(text) ? null : long.Parse(text); string? Text(string text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();
                long? ns = Text(date.Text) == null ? null : checked((DateTimeOffset.Parse(date.Text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal).UtcTicks - DateTime.UnixEpoch.Ticks) * 100);
                query = query with { PathContains = Text(path.Text), Extension = Text(ext.Text), MinimumSize = Number(min.Text), MaximumSize = Number(max.Text), ModifiedAfterNs = ns, Blake3 = Text(hash.Text), ReviewSet = Text(set.Text) }; dialog.Close(); await RefreshQuery();
            }
            catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Filter error"); }
        };
        reset.Click += async (_, _) => { query = new() { ScanId = query.ScanId }; search.Clear(); debounce.Stop(); dialog.Close(); await RefreshQuery(); }; dialog.ShowDialog(this);
    }
    internal static void ShowDifferences(string title, FileRecord old, FileRecord newer)
    {
        using var dialog = new Form { Text = "DriveWitness · " + title, ClientSize = new(1000, 540), StartPosition = FormStartPosition.CenterParent, BackColor = Theme.Background, ForeColor = Theme.Text, Font = Theme.Font };
        var grid = Theme.Table(); grid.Columns.Add("field", "Field"); grid.Columns.Add("old", "Historical / old"); grid.Columns.Add("new", "Current / new"); grid.Columns[0].Width = 140; grid.Columns[1].Width = grid.Columns[2].Width = 410;
        foreach (var field in LiveFileComparison.Differences(old, newer)) { int index = grid.Rows.Add(field.Field, field.Old, field.New); if (field.Changed) grid.Rows[index].DefaultCellStyle.ForeColor = Color.FromArgb(242, 184, 68); }
        dialog.Controls.Add(grid); dialog.ShowDialog();
    }
    internal static void ShowText(string title, string text)
    {
        using var dialog = new Form { Text = "DriveWitness · " + title, ClientSize = new(850, 560), StartPosition = FormStartPosition.CenterParent, Font = Theme.Font, BackColor = Theme.Background };
        var box = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, Text = text, ScrollBars = ScrollBars.Both, WordWrap = false }; dialog.Controls.Add(box); Theme.Apply(dialog); dialog.ShowDialog();
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { queryCancellation?.Cancel(); selectionCancellation?.Cancel(); operationCancellation?.Cancel(); debounce.Dispose(); queryCancellation?.Dispose(); selectionCancellation?.Dispose(); }
        base.Dispose(disposing);
    }
}
