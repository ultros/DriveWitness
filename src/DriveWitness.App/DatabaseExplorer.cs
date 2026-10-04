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
    private CancellationTokenSource? queryCancellation, selectionCancellation, operationCancellation, databaseCancellation;
    private string databaseStatistics = "";
    private DatabaseQueryService? service;
    private IReadOnlyList<FileRecord> rows = [];
    private FileRecord? selected;
    private int generation, selectionGeneration;
    private bool loading, selectionReady;
    private NamedEvidenceView[] savedViews = [];
    private FileRecord? versionBaseline;
    private string verificationTimeline = "";
    private int versionGeneration;
    private bool queryRunning, selectionRunning, versionRunning;
    private void UpdateStopState() { if (!IsDisposed) stop.Enabled = queryRunning || selectionRunning || versionRunning || operationCancellation != null; }
    private EvidenceQuery query = new();
    private IReadOnlyList<ScanEntry> scans = [];
    internal event Action<string>? DatabaseOpened;
    internal event Action<NamedEvidenceView[]>? SavedViewsChanged;
    internal string? DatabasePath => service?.Database;
    internal EvidenceQuery Query => query;
    internal ColumnState[] Columns => WorkspaceState.Capture(table);
    internal int VisibleRecordCount => rows.Count;
    internal bool LastQueryCancelled => queryCancellation?.IsCancellationRequested == true;
    internal bool InspectorMatchesDatabase => selected == null || rows.Contains(selected);
    internal bool LayoutUsable
    {
        get
        {
            var viewport = RectangleToScreen(ClientRectangle);
            var grid = Rectangle.Intersect(viewport, table.RectangleToScreen(table.ClientRectangle));
            var detail = Rectangle.Intersect(viewport, inspector.RectangleToScreen(inspector.ClientRectangle));
            return grid.Width >= 150 && detail.Width >= 180 && grid.Height >= 150 && detail.Height >= 150;
        }
    }
    internal void CancelPendingQuery() => stop.PerformClick();
    internal void RestoreColumns(ColumnState[] columns, int savedDpi = 96) => WorkspaceState.Restore(table, columns, savedDpi);
    internal void RestoreViews(NamedEvidenceView[] views) { savedViews = views; if (service != null) BuildTree(); }

    internal DatabaseExplorer(ColumnState[] columns)
    {
        Dock = DockStyle.Fill; BackColor = Theme.Background; ForeColor = Theme.Text; Font = Theme.Font;
        ((Theme.BufferedGrid)table).EvidenceClipboardContent = () => new DataObject(DataFormats.UnicodeText, SelectedCellText());
        inspector.DrawItem += (_, e) => { using var fill = new SolidBrush(e.Index == inspector.SelectedIndex ? Color.FromArgb(23, 64, 112) : Theme.Surface); e.Graphics.FillRectangle(fill, e.Bounds); TextRenderer.DrawText(e.Graphics, inspector.TabPages[e.Index].Text, Font, e.Bounds, Theme.Text, TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter); };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new(0) };
        layout.ColumnStyles.Add(new(SizeType.Percent, 100));
        foreach (var h in new[] { 52, 68, 0, 48 }) layout.RowStyles.Add(h == 0 ? new(SizeType.Percent, 100) : new(SizeType.Absolute, h)); Controls.Add(layout);
        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 }; heading.Font = new("Segoe UI", 13, FontStyle.Bold); header.Controls.Add(heading); header.Controls.Add(metadata); layout.Controls.Add(header, 0, 0);
        header.ColumnStyles.Add(new(SizeType.Percent, 100));
        header.RowStyles.Add(new(SizeType.Percent, 50)); header.RowStyles.Add(new(SizeType.Percent, 50));
        var toolbar = Theme.Flow(); toolbar.AutoScroll = true; var open = Theme.Button("Open database"); var filters = Theme.Button("Filters"); var changed = Theme.Button("Changed only"); var errors = Theme.Button("Errors"); var columnsButton = Theme.Button("Columns"); var export = Theme.Button("Export"); var saveView = Theme.Button("Save view"); var sets = Theme.Button("Review sets");
        toolbar.Controls.AddRange([search, filters, changed, errors, columnsButton, export, saveView, sets, open]); layout.Controls.Add(toolbar, 0, 1);
        saveView.Click += (_, _) => SaveView(); sets.Click += async (_, _) => await ManageReviewSets();
        var panes = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1 }; panes.ColumnStyles.Add(new(SizeType.Percent, 16)); panes.ColumnStyles.Add(new(SizeType.Percent, 56)); panes.ColumnStyles.Add(new(SizeType.Percent, 28));
        panes.RowStyles.Add(new(SizeType.Percent, 100));
        panes.Controls.Add(Theme.Card(tree, 8), 0, 0); panes.Controls.Add(Theme.Card(table, 0), 1, 0); panes.Controls.Add(Theme.Card(inspector, 8), 2, 0); layout.Controls.Add(panes, 0, 2);
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 }; bottom.ColumnStyles.Add(new(SizeType.Percent, 100)); bottom.ColumnStyles.Add(new(SizeType.Absolute, 320)); bottom.Controls.Add(footer, 0, 0);
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
                versions.Columns.Add("scan", "Scan"); versions.Columns.Add("date", "Observed UTC"); versions.Columns.Add("path", "Path"); versions.Columns.Add("size", "Size"); versions.Columns.Add("b3", "BLAKE3"); versions.Columns.Add("sha", "SHA-256"); versions.Columns.Add("status", "Status"); versions.Columns.Add("method", "Verification");
                panel.Controls.Add(versions, 0, 0); var actions = Theme.Flow(); actions.AutoScroll = true; var diff = Theme.Button("Compare versions"); var baseline = Theme.Button("Set baseline"); var more = Theme.Button("More history"); actions.Controls.AddRange([baseline, diff, more]); panel.Controls.Add(actions, 0, 1); page.Controls.Add(panel);
                baseline.Click += (_, _) => { versionBaseline = versions.CurrentRow?.Tag as FileRecord; footer.Text = versionBaseline == null ? "Select a version first." : $"Comparison baseline: scan #{versionBaseline.ScanId} · {versionBaseline.CanonicalPath}"; };
                diff.Click += (_, _) => { var picked = versions.SelectedRows.Cast<DataGridViewRow>().Select(r => (FileRecord)r.Tag!).OrderBy(r => r.ScanId).ToArray(); if (picked.Length == 2) ShowDifferences("Version comparison", picked[0], picked[1]); else if (versionBaseline != null && versions.CurrentRow?.Tag is FileRecord newer) ShowDifferences("Version comparison", versionBaseline, newer); else footer.Text = "Select two versions, or set a baseline before paging to another version."; };
                more.Click += async (_, _) => { if (selected != null && versionCursor != null) { more.Enabled = false; try { await LoadVersions(selected, true); } catch (Exception ex) { if (!IsDisposed) footer.Text = "History: " + ex.Message; } finally { if (!IsDisposed) more.Enabled = true; } } };
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
        tree.AfterSelect += async (_, e) =>
        {
            if (loading) return;
            if (e.Node?.Tag is NamedEvidenceView view) { await ApplyQuery(view.Query); return; }
            if (e.Node?.Tag is not EvidenceQuery filter) return;
            query = e.Node.Parent?.Text switch
            {
                "SCANS (latest 500)" => filter with { Search = search.Text.Trim() },
                "STATUS" => query with { Status = filter.Status, ChangedOnly = false },
                "VERIFICATION" => query with { Method = filter.Method, HashSource = filter.HashSource },
                _ => filter with { Search = search.Text.Trim(), ScanId = query.ScanId, BaselineScanId = query.BaselineScanId }
            }; await RefreshQuery();
        };
        var viewsMenu = new ContextMenuStrip(); tree.ContextMenuStrip = viewsMenu; tree.NodeMouseClick += (_, e) => { if (e.Button == MouseButtons.Right) tree.SelectedNode = e.Node; };
        viewsMenu.Opening += (_, e) => { viewsMenu.Items.Clear(); if (tree.SelectedNode?.Tag is not NamedEvidenceView view) { e.Cancel = true; return; } var remove = viewsMenu.Items.Add("Remove saved view"); remove.Click += (_, _) => { savedViews = savedViews.Where(v => v != view).ToArray(); SavedViewsChanged?.Invoke(savedViews); BuildTree(); }; };
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
        databaseCancellation?.Cancel(); databaseCancellation?.Dispose(); databaseCancellation = new(); var databaseToken = databaseCancellation.Token; databaseStatistics = "";
        queryCancellation?.Cancel(); selectionCancellation?.Cancel(); operationCancellation?.Cancel(); int opening = ++generation; service = new(path); query = initial ?? new(); search.Text = query.Search; debounce.Stop();
        rows = []; selected = null; lastPage = null; queryRunning = false; table.RowCount = 0; ClearInspector(); previous.Enabled = next.Enabled = false;
        heading.Text = Path.GetFileName(path); metadata.Text = "Reading scan catalog…";
        try
        {
            var local = service; int id = generation; var loaded = await Task.Run(() => local.GetScans(databaseToken), databaseToken); if (IsDisposed || id != generation) return; scans = loaded;
            DatabaseOpened?.Invoke(local.Database);
            if (initial == null && scans.Count > 0) query = query with { ScanId = scans[0].Id };
            BuildTree(); metadata.Text = $"{scans.Count:N0} scans shown · evidence read-only · 256 records per window · health check on demand";
            await RefreshQuery();
            _ = LoadDatabaseStatistics(local, databaseToken);
        }
        catch (Exception ex) { if (!IsDisposed && opening == generation) { footer.Text = "Database unavailable: " + ex.Message; service = null; scans = []; tree.Nodes.Clear(); } }
    }
    private void UpdateMetadata() => metadata.Text = $"{(query.ScanId == null ? "All scans" : "Scan #" + query.ScanId)}{(query.BaselineScanId == null ? "" : " · compared with #" + query.BaselineScanId)} · {scans.Count} scans shown{databaseStatistics} · read-only · 256 records per window";
    private async Task LoadDatabaseStatistics(DatabaseQueryService local, CancellationToken token)
    {
        try
        {
            var health = await Task.Run(() => local.GetHealth(token), token);
            if (IsDisposed || token.IsCancellationRequested || !ReferenceEquals(local, service)) return;
            databaseStatistics = $" · {Convert.ToInt64(health["observations"]):N0} observations · {Theme.Size(Convert.ToInt64(health["bytes"]))}"; UpdateMetadata();
        }
        catch (Exception) { /* Counts are supplemental; explicit health checks present diagnostic failures. */ }
    }
    private void BuildTree()
    {
        loading = true; tree.BeginUpdate(); tree.Nodes.Clear();
        var databaseNode = tree.Nodes.Add("DATABASE"); databaseNode.Nodes.Add(Path.GetFileName(service?.Database));
        var scanNode = tree.Nodes.Add("SCANS (latest 500)"); scanNode.Nodes.Add(new TreeNode("All observations") { Tag = new EvidenceQuery() });
        foreach (var s in scans) scanNode.Nodes.Add(new TreeNode($"#{s.Id}  {s.Started.Replace('T', ' ')[..Math.Min(16, s.Started.Length)]}  {s.Mode}") { Tag = new EvidenceQuery { ScanId = s.Id } });
        var statusNode = tree.Nodes.Add("STATUS"); foreach (string status in new[] { "UNCHANGED", "MODIFIED", "ADDED", "DELETED", "RENAMED", "METADATA_CHANGED", "UNVERIFIED", "UNSTABLE", "ERROR", "LEGACY" }) statusNode.Nodes.Add(new TreeNode(status.Replace('_', ' ')) { Tag = new EvidenceQuery { ScanId = query.ScanId, Status = status } });
        var methodNode = tree.Nodes.Add("VERIFICATION"); foreach (string method in new[] { "FULL_DUAL_HASH", "FULL_BLAKE3", "USN_INCREMENTAL", "CARRIED_FORWARD", "LEGACY" }) methodNode.Nodes.Add(new TreeNode(method.Replace('_', ' ')) { Tag = new EvidenceQuery { ScanId = query.ScanId, Method = method == "CARRIED_FORWARD" ? null : method, HashSource = method == "CARRIED_FORWARD" ? method : null } });
        var saved = tree.Nodes.Add("SAVED VIEWS"); saved.Nodes.Add(new TreeNode("Changed files") { Tag = new EvidenceQuery { ScanId = query.ScanId, ChangedOnly = true } });
        saved.Nodes.Add(new TreeNode("Large files (>100 MiB)") { Tag = new EvidenceQuery { ScanId = query.ScanId, MinimumSize = 100 * 1048576 } });
        saved.Nodes.Add(new TreeNode("Duplicates (BLAKE3)") { Tag = new EvidenceQuery { ScanId = query.ScanId, Duplicates = true } });
        saved.Nodes.Add(new TreeNode("Recently modified (7 days)") { Tag = new EvidenceQuery { ScanId = query.ScanId, ModifiedAfterNs = (DateTime.UtcNow.AddDays(-7).Ticks - DateTime.UnixEpoch.Ticks) * 100 } });
        foreach (string review in new[] { "flagged", "reviewed", "unreviewed" }) saved.Nodes.Add(new TreeNode(char.ToUpperInvariant(review[0]) + review[1..]) { Tag = new EvidenceQuery { ScanId = query.ScanId, Review = review } });
        foreach (string status in new[] { "ADDED", "DELETED", "UNSTABLE", "ERROR" }) saved.Nodes.Add(new TreeNode(status.Replace('_', ' ')) { Tag = new EvidenceQuery { ScanId = query.ScanId, Status = status } });
        saved.Nodes.Add(new TreeNode("Latest file hash mismatch") { Tag = new EvidenceQuery { ScanId = query.ScanId, HashMismatch = true } });
        foreach (var view in savedViews.Where(v => string.Equals(v.Database, service?.Database, StringComparison.OrdinalIgnoreCase))) saved.Nodes.Add(new TreeNode(view.Name) { Tag = view });
        databaseNode.Expand(); scanNode.Expand(); statusNode.Expand(); saved.Expand(); tree.EndUpdate(); loading = false;
    }
    internal async Task ApplyQuery(EvidenceQuery filter) { query = filter; search.Text = query.Search; debounce.Stop(); await RefreshQuery(); }
    internal void FocusSearch() => search.Focus();
    internal async Task RefreshQuery() { cursor = null; cursors.Clear(); await Fetch(); }
    private async Task Fetch()
    {
        if (service == null) return; queryCancellation?.Cancel(); queryCancellation?.Dispose(); queryCancellation = new(); var token = queryCancellation.Token;
        selectionCancellation?.Cancel(); int id = ++generation; var local = service; var filter = query; var after = cursor;
        queryRunning = true; UpdateStopState(); previous.Enabled = next.Enabled = false; footer.Text = "Querying evidence…";
        rows = []; selected = null; table.RowCount = 0; ClearInspector();
        var time = Stopwatch.StartNew();
        try
        {
            var page = await Task.Run(() => local.SearchFiles(filter, after, token: token), token); if (IsDisposed || id != generation || token.IsCancellationRequested) return;
            rows = page.Rows; lastPage = page; table.RowCount = rows.Count;
            UpdateMetadata();
            foreach (DataGridViewColumn col in table.Columns) col.HeaderCell.SortGlyphDirection = col.Name == query.Sort ? query.Descending ? SortOrder.Descending : SortOrder.Ascending : SortOrder.None;
            footer.Text = rows.Count == 0 ? "No records match these filters. Use SCANS → All observations to reset." : $"Window {cursors.Count + 1:N0} · {rows.Count:N0} records · query {time.Elapsed.TotalMilliseconds:N0} ms · {(page.HasMore ? "more available" : "end of results")}";
            previous.Enabled = cursors.Count > 0; next.Enabled = page.HasMore;
        }
        catch (Exception ex) { if (!IsDisposed && id == generation) footer.Text = token.IsCancellationRequested ? "Query cancelled." : "Query failed: " + ex.Message; }
        finally { if (!IsDisposed && id == generation) { queryRunning = false; UpdateStopState(); } }
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
        selectionGeneration++; versionGeneration++; selectionRunning = versionRunning = false; selectionReady = false; saveNote.Enabled = false; versions.Rows.Clear(); versionCursor = null; versionBaseline = null; verificationTimeline = ""; UpdateStopState();
        foreach (var box in details.Values) box.Text = "Select an evidence record."; note.Clear(); reviewSet.Clear(); flagged.Checked = reviewed.Checked = false;
    }
    private async Task SelectRecord()
    {
        var row = CurrentRecord(); if (row == null || row == selected || service == null) return; selected = row; ClearInspector();
        selectionCancellation?.Cancel(); selectionCancellation?.Dispose(); selectionCancellation = new(); int id = selectionGeneration; var token = selectionCancellation.Token;
        selectionRunning = true; UpdateStopState();
        details["Summary"].Text = $"{Path.GetFileName(row.CanonicalPath)}\r\n\r\n{row.CanonicalPath}\r\n\r\nSTATUS\r\n{row.Status}\r\n\r\nVERIFICATION\r\n{row.Method}\r\n\r\nSIZE\r\n{Theme.Size(row.Size)} ({row.Size:N0} bytes)\r\n\r\nSCAN\r\n{row.ScanId}\r\n\r\nVOLUME\r\n{row.VolumeSerial ?? "Unavailable"}\r\n\r\nFILE ID\r\n{row.FileId ?? "Unavailable"}\r\n\r\nCanonical paths are stored observations. Live reads can affect access times.";
        string observationTime;
        try { observationTime = EvidenceDatabase.Decompress(row.ScanTime) ?? "Unavailable"; } catch (Exception ex) when (ex is IOException or System.Text.DecoderFallbackException) { observationTime = "Invalid compressed display field"; }
        details["Hashes"].Text = $"BLAKE3\r\n{Theme.Hash(row.Blake3, true)}\r\n\r\nObservation scan: {row.ScanId}\r\nMethod: {row.Method}\r\n\r\nSHA-256\r\n{Theme.Hash(row.Sha256, true)}\r\n\r\nOrigin scan: {row.Sha256OriginScan}\r\nProvenance: {row.Sha256Provenance}\r\nCarried forward: {(row.Sha256Provenance == "CARRIED_FORWARD" ? "Yes" : "No")}\r\n\r\nLegacy SHA-1\r\n{row.LegacySha1 ?? "Unavailable"}\r\n\r\nBackend: CPU for C# collections; historical backend not separately recorded.\r\nObservation time: {observationTime}";
        details["Metadata"].Text = $"CREATED\r\n{Theme.Time(row.CreatedNs)}\r\n\r\nMODIFIED\r\n{Theme.Time(row.ModifiedNs)}\r\n\r\nACCESSED\r\n{Theme.Time(row.AccessedNs)}\r\n\r\nATTRIBUTES\r\n{row.Attributes}\r\n\r\nHARD LINKS\r\n{row.HardlinkCount}\r\n\r\nFIRST SEEN SCAN\r\n{row.FirstSeenScan}\r\n\r\nLAST SEEN SCAN\r\n{row.LastSeenScan}";
        details["Errors"].Text = row.ErrorCode == null ? "No error is recorded for this observation." : row.ErrorCode + "\r\n\r\n" + row.ErrorMessage;
        try
        {
            string db = service.Database; var reviewData = await Task.Run(() => { var store = new ReviewStore(db); return (Review: store.Get(row), Events: store.GetVerifications(row)); }, token); var review = reviewData.Review;
            if (IsDisposed || token.IsCancellationRequested || id != selectionGeneration) return;
            flagged.Checked = review?.Flagged ?? false; reviewed.Checked = review?.Reviewed ?? false; note.Text = review?.Note ?? ""; reviewSet.Text = review?.Set ?? ""; selectionReady = true; saveNote.Enabled = true;
            verificationTimeline = VerificationHistory(reviewData.Events);
            await LoadVersions(row, false);
        }
        catch (Exception ex) { if (!IsDisposed && id == selectionGeneration) footer.Text = token.IsCancellationRequested ? "Selection cancelled" : ex.Message; }
        finally { if (!IsDisposed && id == selectionGeneration) { selectionRunning = false; UpdateStopState(); } }
    }
    private static string VerificationHistory(IReadOnlyList<VerificationEvent> events) => "\r\n\r\nVERIFICATION EVENTS (latest 100 for this observation)\r\n" + string.Join("\r\n\r\n", events.Reverse().Select(v =>
    {
        try { using var doc = JsonDocument.Parse(v.Result); return $"Observed: {doc.RootElement.GetProperty("observed_utc").GetString()} · {doc.RootElement.GetProperty("result").GetString()}\r\nSaved: {v.Created} · Analyst: {v.Analyst}"; }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { return $"Saved: {v.Created} · Analyst: {v.Analyst}\r\nUnreadable verification event: {ex.Message}"; }
    }));
    private async Task LoadVersions(FileRecord row, bool more)
    {
        if (service == null || selectionCancellation == null) return; var local = service; int id = selectionGeneration, window = ++versionGeneration; var token = selectionCancellation.Token; var after = more ? versionCursor : null;
        versionRunning = true; UpdateStopState(); EvidencePage page;
        try { page = await Task.Run(() => local.GetFileVersions(row, after, token), token); }
        finally { if (!IsDisposed && window == versionGeneration) { versionRunning = false; UpdateStopState(); } }
        if (IsDisposed || id != selectionGeneration || window != versionGeneration || token.IsCancellationRequested) return;
        versions.Rows.Clear(); foreach (var r in page.Rows) { string date; try { date = EvidenceDatabase.Decompress(r.ScanTime) ?? scans.FirstOrDefault(s => s.Id == r.ScanId)?.Started ?? "Unavailable"; } catch (IOException) { date = "Invalid display field"; } int index = versions.Rows.Add(r.ScanId, date, r.CanonicalPath, Theme.Size(r.Size), Theme.Hash(r.Blake3), Theme.Hash(r.Sha256), r.Status ?? "—", r.Method ?? "—"); versions.Rows[index].Tag = r; }
        versionCursor = page.HasMore ? page.Next : null;
        details["Timeline"].Text = $"OBSERVATION HISTORY\r\nFirst seen scan: {row.FirstSeenScan} · Last seen scan: {row.LastSeenScan}\r\n{page.Rows.Count} observations in this window{(page.HasMore ? " · more in Versions" : "")}\r\n\r\n" + string.Join("\r\n\r\n", page.Rows.Reverse().Select(r => $"Scan #{r.ScanId} · {scans.FirstOrDefault(s => s.Id == r.ScanId)?.Started ?? "date unavailable"}\r\n{r.Status} · {r.Method}\r\n{r.CanonicalPath}\r\nCreated: {Theme.Time(r.CreatedNs)}\r\nModified: {Theme.Time(r.ModifiedNs)}\r\nAccessed: {Theme.Time(r.AccessedNs)}\r\nBLAKE3: {Theme.Hash(r.Blake3)}\r\nSHA-256: {Theme.Hash(r.Sha256)}")) + verificationTimeline;
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
        bool canRehash = row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal);
        Add(verify, "Recalculate BLAKE3 (changed SHA-256 if needed)", EvidenceActionKind.LiveFilesystemReadOnly, async () => await LiveCompare(row, false), canRehash);
        Add(verify, "Recalculate SHA-256 (single-read dual hash)", EvidenceActionKind.LiveFilesystemReadOnly, async () => await LiveCompare(row, true), canRehash);
        var filesystem = Group("Filesystem"); Add(filesystem, "Open file location", EvidenceActionKind.LiveFilesystemReadOnly, async () => await Reveal(row, true), row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal)); Add(filesystem, "Open containing folder", EvidenceActionKind.LiveFilesystemReadOnly, async () => await Reveal(row, false), !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal));
        Add(filesystem, "Properties", EvidenceActionKind.LiveFilesystemReadOnly, async () =>
        {
            try { string? path = await Task.Run(() => LiveFileComparison.DiskPath(row)); if (path != null && await Task.Run(() => File.Exists(path))) WindowsFileActions.Properties(path, Handle); else footer.Text = "Historical file is not currently available."; }
            catch (Exception ex) { footer.Text = ex.Message; }
        }, row.Status != "DELETED" && !row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal));
        var review = Group("Review"); Add(review, "Toggle flag", EvidenceActionKind.Annotation, async () => await Annotate(row, "flag")); Add(review, "Mark reviewed", EvidenceActionKind.Annotation, async () => await Annotate(row, "reviewed")); Add(review, "Add note", EvidenceActionKind.Annotation, () => { inspector.SelectedIndex = 6; note.Focus(); }); Add(review, "Add to review set", EvidenceActionKind.Annotation, async () => { string? set = Prompt("Add to review set", "Set name", ""); if (!string.IsNullOrWhiteSpace(set)) await Annotate(row, "set", set); });
        var export = Group("Export"); Add(export, "Selected record", EvidenceActionKind.Export, async () => await Export(true, [row])); Add(export, "Selected rows", EvidenceActionKind.Export, async () => await Export(true)); Add(export, "Evidence report (HTML)", EvidenceActionKind.Export, async () => await Export(true, null, "html"));
    }
    private async Task ComparePrevious(FileRecord row)
    {
        if (service == null) return;
        try { var local = service; var older = await Task.Run(() => local.GetPreviousVersion(row)); if (IsDisposed || service != local) return; if (older == null) footer.Text = "No earlier observation is recorded for this file identity."; else ShowDifferences("Previous observation", older, row); }
        catch (Exception ex) { if (!IsDisposed) footer.Text = ex.Message; }
    }
    private async Task Annotate(FileRecord row, string action, string? set = null)
    {
        if (service == null) return; string db = service.Database;
        bool editing = row == selected && selectionReady; string? draftNote = editing ? note.Text : null, draftSet = editing ? reviewSet.Text : null; bool? draftFlag = editing ? flagged.Checked : null, draftReviewed = editing ? reviewed.Checked : null;
        try
        {
            await Task.Run(() => { var store = new ReviewStore(db); var review = store.Get(row); bool flag = draftFlag ?? review?.Flagged ?? false; store.Save(row, action == "flag" ? !flag : flag, action == "reviewed" || (draftReviewed ?? review?.Reviewed ?? false), draftNote ?? review?.Note ?? "", set ?? draftSet ?? review?.Set ?? ""); });
            if (IsDisposed || service?.Database != db) return; await RefreshQuery(); footer.Text = "Analyst review updated; scan evidence is unchanged.";
        }
        catch (Exception ex) { if (!IsDisposed) footer.Text = "Review: " + ex.Message; }
    }
    internal async Task<bool> ReviewContextPreservesDraft()
    {
        if (selected == null || service == null || !selectionReady) return false; var row = selected; string db = service.Database;
        note.Text = "GUI regression note"; reviewSet.Text = "GUI case"; flagged.Checked = true; await Annotate(row, "reviewed");
        var review = await Task.Run(() => new ReviewStore(db).Get(row)); return review is { Flagged: true, Reviewed: true, Note: "GUI regression note", Set: "GUI case" };
    }
    private async Task LiveCompare(FileRecord row, bool dual)
    {
        if (service == null || operationCancellation != null) return; string db = service.Database; operationCancellation = new(); var control = new ScanControl(); using var cancel = operationCancellation.Token.Register(control.Cancel); UpdateStopState(); footer.Text = "Reading current file…";
        try
        {
            var result = await Task.Run(() => LiveFileComparison.Compare(row, dual, control)); if (IsDisposed || service?.Database != db || operationCancellation.IsCancellationRequested) return;
            if (result.Current == null) ShowText(result.Result, result.Error ?? result.Result);
            else ShowDifferences(result.Result, row, result.Current);
            using var dialog = new Form { Text = "Save verification event", ClientSize = new(560, 120), StartPosition = FormStartPosition.CenterParent, BackColor = Theme.Background, ForeColor = Theme.Text, Font = Theme.Font };
            var body = Theme.Label($"{result.Result} · observed {result.ObservedUtc}\nStore this result in the separate review database?"); body.Dock = DockStyle.Fill; dialog.Controls.Add(body); var save = Theme.Button("Save new verification event"); save.Dock = DockStyle.Bottom; dialog.Controls.Add(save); bool persist = false; save.Click += (_, _) => { persist = true; dialog.Close(); }; dialog.ShowDialog(this);
            if (persist)
            {
                await Task.Run(() => new ReviewStore(db).AppendVerification(row, result));
                if (!IsDisposed && service?.Database == db && selected == row)
                {
                    var events = await Task.Run(() => new ReviewStore(db).GetVerifications(row));
                    if (!IsDisposed && service?.Database == db && selected == row) { verificationTimeline = VerificationHistory(events); await LoadVersions(row, false); }
                }
            }
            if (!IsDisposed && service?.Database == db) footer.Text = result.Result + (persist ? " · new verification event saved" : " · historical evidence unchanged");
        }
        catch (Exception ex) { if (!IsDisposed) footer.Text = "Live verification: " + ex.Message; }
        finally { operationCancellation?.Dispose(); operationCancellation = null; UpdateStopState(); }
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
        var local = service; var filter = query; string output = dialog.FileName; operationCancellation = new(); var token = operationCancellation.Token; UpdateStopState(); footer.Text = "Streaming evidence export…";
        try { await Task.Run(() => local.Export(filter, output, format, token, picked), token); if (!IsDisposed && service == local) footer.Text = "Exported " + output; }
        catch (Exception ex) { if (!IsDisposed && service == local) footer.Text = token.IsCancellationRequested ? "Export cancelled; output was not replaced." : ex.Message; }
        finally { operationCancellation.Dispose(); operationCancellation = null; UpdateStopState(); }
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
    private void SaveView()
    {
        if (service == null) return; string? name = Prompt("Save evidence view", "View name", ""); if (name == null) return;
        if (name.Length is < 1 or > 100) { footer.Text = "View names must contain 1–100 characters."; return; }
        savedViews = savedViews.Where(v => !(v.Name == name && string.Equals(v.Database, service.Database, StringComparison.OrdinalIgnoreCase))).Append(new(name, service.Database, query)).TakeLast(100).ToArray();
        SavedViewsChanged?.Invoke(savedViews); BuildTree(); footer.Text = "Saved view: " + name;
    }
    private async Task ManageReviewSets()
    {
        if (service == null) return; string db = service.Database;
        try
        {
            var sets = await Task.Run(() => new ReviewStore(db).GetSets()); if (IsDisposed) return;
            using var dialog = new Form { Text = "Review sets · separate analyst storage", ClientSize = new(550, 400), StartPosition = FormStartPosition.CenterParent, Font = Theme.Font, BackColor = Theme.Background, ForeColor = Theme.Text };
            var list = new ListBox { Dock = DockStyle.Fill, BackColor = Theme.Surface, ForeColor = Theme.Text }; list.Items.AddRange(sets.ToArray()); dialog.Controls.Add(list);
            var actions = Theme.Flow(); actions.Dock = DockStyle.Bottom; actions.Height = 48; Button open = Theme.Button("Open set"), rename = Theme.Button("Rename"), remove = Theme.Button("Remove membership"); actions.Controls.AddRange([open, rename, remove]); dialog.Controls.Add(actions);
            open.Click += async (_, _) => { if (list.SelectedItem is string name) { dialog.Close(); await ApplyQuery(new() { ReviewSet = name }); } };
            rename.Click += async (_, _) => { if (list.SelectedItem is not string oldName) return; string? name = Prompt("Rename review set", "Set name", oldName); if (name == null) return; try { await Task.Run(() => new ReviewStore(db).RenameSet(oldName, name)); dialog.Close(); } catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Review set"); } };
            remove.Click += async (_, _) => { if (list.SelectedItem is not string name || MessageBox.Show(dialog, "Remove membership in this set? Analyst notes and scan evidence are retained.", "Remove review set membership", MessageBoxButtons.YesNo) != DialogResult.Yes) return; try { await Task.Run(() => new ReviewStore(db).RemoveSet(name)); dialog.Close(); } catch (Exception ex) { MessageBox.Show(dialog, ex.Message, "Review set"); } };
            if (sets.Count > 0) list.SelectedIndex = 0; else { list.Items.Add("Create a set name in a selected record's Notes tab."); open.Enabled = rename.Enabled = remove.Enabled = false; } dialog.ShowDialog(this);
        }
        catch (Exception ex) { if (!IsDisposed) footer.Text = "Review sets: " + ex.Message; }
    }
    internal static string? Prompt(string title, string caption, string value)
    {
        using var dialog = new Form { Text = "DriveWitness · " + title, ClientSize = new(520, 150), StartPosition = FormStartPosition.CenterParent, Font = Theme.Font, BackColor = Theme.Background, ForeColor = Theme.Text };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, Padding = new(16) }; layout.RowStyles.Add(new(SizeType.Absolute, 28)); layout.RowStyles.Add(new(SizeType.Absolute, 35)); layout.RowStyles.Add(new(SizeType.Percent, 100)); var input = new TextBox { Text = value, Dock = DockStyle.Fill };
        var save = Theme.Button("Save", true); save.DialogResult = DialogResult.OK; layout.Controls.Add(Theme.Label(caption), 0, 0); layout.Controls.Add(input, 0, 1); layout.Controls.Add(save, 0, 2); dialog.Controls.Add(layout); dialog.AcceptButton = save; Theme.Apply(dialog);
        return dialog.ShowDialog() == DialogResult.OK ? input.Text.Trim() : null;
    }
    private void AdvancedFilters()
    {
        using var dialog = new Form { Text = "Evidence filters", ClientSize = new(560, 620), StartPosition = FormStartPosition.CenterParent, Font = Theme.Font, BackColor = Theme.Background, ForeColor = Theme.Text };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(20), AutoScroll = true }; layout.ColumnStyles.Add(new(SizeType.Absolute, 180)); layout.ColumnStyles.Add(new(SizeType.Percent, 100)); dialog.Controls.Add(layout); int i = 0;
        TextBox Field(string text, string value) { var box = new TextBox { Dock = DockStyle.Fill, Text = value }; layout.RowStyles.Add(new(SizeType.Absolute, 40)); layout.Controls.Add(Theme.Label(text), 0, i); layout.Controls.Add(box, 1, i++); return box; }
        var path = Field("Path contains", query.PathContains ?? ""); var ext = Field("Extension", query.Extension ?? ""); var min = Field("Minimum bytes", query.MinimumSize?.ToString() ?? ""); var max = Field("Maximum bytes", query.MaximumSize?.ToString() ?? ""); var date = Field("Modified after UTC", query.ModifiedAfterNs == null ? "" : EvidenceDatabase.Iso(query.ModifiedAfterNs.Value)); var hash = Field("BLAKE3 prefix", query.Blake3 ?? ""); var set = Field("Review set", query.ReviewSet ?? "");
        var modifiedBefore = Field("Modified before UTC", query.ModifiedBeforeNs == null ? "" : EvidenceDatabase.Iso(query.ModifiedBeforeNs.Value)); var createdAfter = Field("Created after UTC", query.CreatedAfterNs == null ? "" : EvidenceDatabase.Iso(query.CreatedAfterNs.Value)); var createdBefore = Field("Created before UTC", query.CreatedBeforeNs == null ? "" : EvidenceDatabase.Iso(query.CreatedBeforeNs.Value)); var sha = Field("SHA-256 prefix", query.Sha256 ?? ""); var id = Field("File ID", query.FileId ?? "");
        var apply = Theme.Button("Apply filters", true); var reset = Theme.Button("Reset filters"); layout.Controls.Add(reset, 0, i); layout.Controls.Add(apply, 1, i); Theme.Apply(dialog);
        apply.Click += async (_, _) =>
        {
            try
            {
                long? Number(string text) => string.IsNullOrWhiteSpace(text) ? null : long.Parse(text); string? Text(string text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();
                long? Date(string text) => Text(text) == null ? null : checked((DateTimeOffset.Parse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal).UtcTicks - DateTime.UnixEpoch.Ticks) * 100);
                query = query with { PathContains = Text(path.Text), Extension = Text(ext.Text), MinimumSize = Number(min.Text), MaximumSize = Number(max.Text), ModifiedAfterNs = Date(date.Text), ModifiedBeforeNs = Date(modifiedBefore.Text), CreatedAfterNs = Date(createdAfter.Text), CreatedBeforeNs = Date(createdBefore.Text), Blake3 = Text(hash.Text), Sha256 = Text(sha.Text), FileId = Text(id.Text), ReviewSet = Text(set.Text) }; dialog.Close(); await RefreshQuery();
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
        var box = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, Text = text.ReplaceLineEndings("\r\n"), ScrollBars = ScrollBars.Both, WordWrap = false }; dialog.Controls.Add(box); Theme.Apply(dialog); dialog.ShowDialog();
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { databaseCancellation?.Cancel(); queryCancellation?.Cancel(); selectionCancellation?.Cancel(); operationCancellation?.Cancel(); debounce.Dispose(); databaseCancellation?.Dispose(); queryCancellation?.Dispose(); selectionCancellation?.Dispose(); }
        base.Dispose(disposing);
    }
}
