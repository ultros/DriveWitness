using System.Text.Json;
using DriveWitness.Core;

namespace DriveWitness.App;

internal sealed partial class MainForm
{
    private readonly Dictionary<string, Control> pages = new();
    private readonly Dictionary<string, Button> navigation = new();
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill, Padding = new(18, 14, 18, 14) };
    private readonly Label pageTitle = Theme.Label("New Scan"), persistentScan = Theme.Label("Ready · no active scan", true), overviewMetrics = Theme.Label("No completed baseline is open.", true);
    private readonly Button topPause = Theme.Button("Pause");
    private readonly DataGridView historyTable = Theme.Table(), recentTable = Theme.Table(), volumeTable = Theme.Table();
    private readonly DataGridView driveGrid = Theme.Table();
    private readonly PerformanceGraph previewGraph = new() { Dock = DockStyle.Fill };
    private readonly Label previewSummary = Theme.Label("Ready to establish an evidence baseline.\nSelect a volume or folder, choose an evidence database, then start scanning.", true);
    private readonly Label scanHeading = Theme.Label("SCAN INSTRUMENTATION"), scanFraction = Theme.Label("Waiting for a scan", true), scanMemory = Theme.Label("Memory — · Disk — · GPU Off", true);
    private readonly ScanProgressBar progressBar = new() { Dock = DockStyle.Fill };
    private readonly TrackBar liveThrottle = new() { Minimum = 0, Maximum = 100, Value = 60, TickStyle = TickStyle.None, Dock = DockStyle.Fill, AutoSize = false, AccessibleName = "Active scan resource budget" };
    private readonly Dictionary<string, Label> scanMetrics = new();
    private readonly ComboBox baselineScan = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 380 }, comparisonScan = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 380 };
    private readonly Label comparisonSummary = Theme.Label("Select two completed scans from the current database.", true);
    private readonly TextBox capabilitiesText = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, WordWrap = true, Text = "Hardware discovery runs after the window appears." };
    private IReadOnlyList<VolumeInfo> detectedVolumes = [];
    private IReadOnlyList<ScanEntry> catalog = [];
    private Dictionary<string, object?>? capabilityData;
    private WorkspaceState workspace = new();
    private DatabaseExplorer explorer = null!;
    private string currentPage = "New Scan";
    private bool refreshingOverview, synchronizingBudget;
    private readonly TextBox historySearch = new() { PlaceholderText = "Filter this scan catalog…", Width = 310 };
    private readonly CheckBox showHiddenScans = new() { Text = "Show removed entries", AutoSize = true };
    private long? preferredBaseline;
    private CancellationTokenSource? evidenceCheckCancellation, comparisonCancellation;
    private string EvidencePath => explorer.DatabasePath ?? database.Text;

    private void BuildShell()
    {
        Text = "DriveWitness · Forensic Baseline & Integrity Monitor"; ClientSize = new(1460, 920); MinimumSize = new(1200, 760);
        StartPosition = FormStartPosition.CenterScreen; AutoScaleMode = AutoScaleMode.Dpi; Font = Theme.Font; BackColor = Background; ForeColor = TextColor; KeyPreview = true;
        DpiChanged += (_, _) => BeginInvoke(ConstrainToScreen);
        using var iconStream = typeof(MainForm).Assembly.GetManifestResourceStream("DriveWitness.Icon"); if (iconStream != null) Icon = new Icon(iconStream);
        if (selfTest != null) { ShowInTaskbar = false; Opacity = 0; }
        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, Margin = new(0), Padding = new(0) };
        shell.ColumnStyles.Add(new(SizeType.Absolute, 184)); shell.ColumnStyles.Add(new(SizeType.Percent, 100)); shell.RowStyles.Add(new(SizeType.Absolute, 64)); shell.RowStyles.Add(new(SizeType.Percent, 100)); shell.RowStyles.Add(new(SizeType.Absolute, 43)); Controls.Add(shell);
        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 5, Padding = new(18, 6, 18, 6), BackColor = Theme.Surface };
        header.ColumnStyles.Add(new(SizeType.Absolute, 38)); header.ColumnStyles.Add(new(SizeType.Absolute, 176)); header.ColumnStyles.Add(new(SizeType.Absolute, 190)); header.ColumnStyles.Add(new(SizeType.Percent, 100)); header.ColumnStyles.Add(new(SizeType.Absolute, 292));
        header.RowCount = 1; header.RowStyles.Add(new(SizeType.Percent, 100));
        var brand = new PictureBox { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.CenterImage, Image = Icon?.ToBitmap(), AccessibleName = "DriveWitness shield and drive" }; header.Controls.Add(brand, 0, 0);
        var product = Theme.Label("DriveWitness"); product.Font = new("Segoe UI", 17, FontStyle.Bold); product.ForeColor = Theme.Blue; header.Controls.Add(product, 1, 0); pageTitle.Font = new("Segoe UI", 12, FontStyle.Bold); header.Controls.Add(pageTitle, 2, 0); header.Controls.Add(persistentScan, 3, 0);
        var topActions = Theme.Flow(); topActions.BackColor = Theme.Surface; var palette = Theme.Button("Ctrl+K"); var help = Theme.Button("Help / About"); topPause.Enabled = false; topPause.Click += (_, _) => TogglePause(); topActions.Controls.AddRange([topPause, palette, help]); header.Controls.Add(topActions, 4, 0); shell.Controls.Add(header, 0, 0); shell.SetColumnSpan(header, 2);
        var sidebar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, Padding = new(10, 14, 10, 10), BackColor = Color.FromArgb(12, 20, 31) }; sidebar.RowStyles.Add(new(SizeType.Percent, 100)); sidebar.RowStyles.Add(new(SizeType.Absolute, 54));
        var nav = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
        foreach (string name in new[] { "Overview", "New Scan", "Active Scan", "Scan History", "Database Explorer", "Compare", "Reports", "Performance", "Benchmark", "Capabilities", "Settings" })
        { var b = Theme.Button(name); b.AutoSize = false; b.Size = new(157, 38); b.Margin = new(0, 0, 0, 5); b.TextAlign = ContentAlignment.MiddleLeft; b.FlatAppearance.BorderSize = 0; navigation[name] = b; b.Click += (_, _) => Navigate(name); nav.Controls.Add(b); }
        sidebar.Controls.Add(nav, 0, 0); var ready = Theme.Label("v3.1.1\nReady · Windows 11", true); sidebar.Controls.Add(ready, 0, 1); shell.Controls.Add(sidebar, 0, 1); shell.Controls.Add(pageHost, 1, 1);
        var attribution = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new(14, 8, 0, 0), BackColor = Theme.Surface };
        attribution.Controls.Add(new Label { Text = "DriveWitness by Jesse Lee Shelley · Copyright © 2026 · All Rights Reserved.", AutoSize = true, ForeColor = Theme.Muted, Padding = new(0, 3, 14, 0) });
        LinkLabel Link(string text, string url) { var l = new LinkLabel { Text = text, AutoSize = true, LinkColor = Color.FromArgb(105, 169, 255), ActiveLinkColor = Theme.Cyan, Padding = new(0, 3, 14, 0) }; l.LinkClicked += (_, _) => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true })?.Dispose(); return l; }
        attribution.Controls.Add(Link("LinkedIn", "https://linkedin.com/in/jesse-shelley")); attribution.Controls.Add(Link("Project", "https://github.com/ultros/DriveWitness")); var license = Theme.Button("License"); license.Font = new("Segoe UI", 8); license.MinimumSize = new(55, 23); license.Padding = new(3, 0, 3, 0); license.Click += (_, _) => About(); attribution.Controls.Add(license); shell.Controls.Add(attribution, 0, 2); shell.SetColumnSpan(attribution, 2);
        explorer = new([]); explorer.DatabaseOpened += path => { if (!busy) database.Text = path; workspace = workspace with { RecentDatabases = new[] { path }.Concat(workspace.RecentDatabases).Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToArray() }; };
        explorer.SavedViewsChanged += async views => { workspace = workspace with { SavedViews = views }; try { var state = workspace; await Task.Run(() => state.Save()); } catch (Exception ex) { if (!IsDisposed) status.Text = "Saved views: " + ex.Message; } };
        pages["New Scan"] = BuildNewScan(); pages["Active Scan"] = BuildActiveScan(); pages["Overview"] = BuildOverview(); pages["Scan History"] = BuildHistory(); pages["Database Explorer"] = explorer;
        pages["Compare"] = BuildCompare(); pages["Reports"] = BuildReports(); pages["Performance"] = BuildPerformance(); pages["Benchmark"] = BuildBenchmark(); pages["Capabilities"] = Theme.Card(capabilitiesText); pages["Settings"] = BuildSettings();
        foreach (var page in pages.Values) { page.Dock = DockStyle.Fill; page.Visible = false; pageHost.Controls.Add(page); }
        start.BackColor = Theme.Blue; start.FlatAppearance.BorderColor = Theme.Blue;
        palette.Click += (_, _) => CommandPalette(); help.Click += (_, _) => About();
        liveThrottle.ValueChanged += (_, _) => { if (!synchronizingBudget) throttle.Value = liveThrottle.Value; };
        throttle.ValueChanged += (_, _) => { synchronizingBudget = true; liveThrottle.Value = throttle.Value; synchronizingBudget = false; };
        HandleCreated += (_, _) => Theme.DarkTitle(this);
        KeyDown += async (_, e) =>
        {
            if (e.Control && e.KeyCode == Keys.K) { e.SuppressKeyPress = true; CommandPalette(); }
            else if (e.Control && e.KeyCode == Keys.O) { e.SuppressKeyPress = true; Navigate("Database Explorer"); await explorer.ChooseDatabase(); await RefreshOverview(); }
            else if (e.Control && e.KeyCode == Keys.F) { e.SuppressKeyPress = true; Navigate("Database Explorer"); explorer.FocusSearch(); }
            else if (e.Control && e.KeyCode == Keys.C && currentPage == "Database Explorer" && ActiveControl is not TextBox && !ContainsFocusedText(explorer)) { e.SuppressKeyPress = true; if (e.Shift) explorer.CopyRecord(); else explorer.CopyCells(); }
            else if (e.KeyCode == Keys.F5) { e.SuppressKeyPress = true; if (currentPage == "Database Explorer") await explorer.RefreshQuery(); else await RefreshOverview(); }
        };
        Navigate("New Scan");
    }
    private static bool ContainsFocusedText(Control c) => c is TextBox { Focused: true } || c.Controls.Cast<Control>().Any(ContainsFocusedText);
    private static TableLayoutPanel Page(string title, string subtitle, params int[] heights)
    {
        var p = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = heights.Length + 1, AutoScroll = true };
        p.ColumnStyles.Add(new(SizeType.Percent, 100));
        p.RowStyles.Add(new(SizeType.Absolute, 70)); var h = Theme.Label(title + "\n" + subtitle); h.Font = new("Segoe UI", 13, FontStyle.Bold); p.Controls.Add(h, 0, 0);
        foreach (int height in heights) p.RowStyles.Add(height == 0 ? new(SizeType.Percent, 100) : new(SizeType.Absolute, height)); return p;
    }
    private Control BuildNewScan()
    {
        var page = Page("Scan Drives", "Create or verify a forensic baseline with cryptographic integrity.", 80, 185, 54, 94, 50, 48, 0);
        var modes = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3 }; for (int i = 0; i < 3; i++) modes.ColumnStyles.Add(new(SizeType.Percent, 33.33f));
        modes.RowCount = 1; modes.RowStyles.Add(new(SizeType.Percent, 100));
        mode.Items.AddRange(["Verify", "Quick", "Forensic"]); mode.SelectedIndex = 0; gpu.Items.AddRange(["Auto", "Off", "Force"]); gpu.SelectedIndex = 0;
        var buttons = new Dictionary<string, Button>();
        foreach (var item in new[] { ("Quick", "USN-assisted incremental"), ("Verify", "BLAKE3 + content changes"), ("Forensic", "Full BLAKE3 + SHA-256") })
        { var b = Theme.Button(item.Item1 + "\n" + item.Item2, item.Item1 == "Verify"); b.Dock = DockStyle.Fill; b.Margin = new(0, 0, 10, 10); b.Click += (_, _) => mode.SelectedItem = item.Item1; buttons[item.Item1] = b; modes.Controls.Add(b); }
        mode.SelectedIndexChanged += (_, _) => { foreach (var pair in buttons) { pair.Value.BackColor = mode.Text == pair.Key ? Theme.Blue : Theme.Surface; pair.Value.FlatAppearance.BorderColor = mode.Text == pair.Key ? Theme.Blue : Theme.Border; } }; page.Controls.Add(modes, 0, 1);
        var driveArea = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 }; driveArea.RowStyles.Add(new(SizeType.Absolute, 32)); driveArea.RowStyles.Add(new(SizeType.Percent, 100)); driveArea.Controls.Add(Theme.Label("AVAILABLE VOLUMES / SELECTED FOLDERS   ·   Drive   /   Label   /   Filesystem   /   Used & capacity   /   Storage", true), 0, 0);
        driveGrid.ReadOnly = false; driveGrid.MultiSelect = false; driveGrid.Columns.Add(new DataGridViewCheckBoxColumn { Name = "Selected", HeaderText = "", Width = 35 });
        foreach (var col in new[] { ("Drive / folder", 120), ("Label", 220), ("Filesystem", 90), ("Capacity", 100), ("Used", 100), ("Storage", 90), ("USN", 120), ("Baseline", 150) }) { int i = driveGrid.Columns.Add(col.Item1, col.Item1); driveGrid.Columns[i].Width = col.Item2; driveGrid.Columns[i].ReadOnly = true; }
        driveGrid.CurrentCellDirtyStateChanged += (_, _) => { if (driveGrid.IsCurrentCellDirty) driveGrid.CommitEdit(DataGridViewDataErrorContexts.Commit); };
        driveGrid.CellValueChanged += (_, e) => { if (e.ColumnIndex == 0 && e.RowIndex >= 0 && driveGrid.Rows[e.RowIndex].Tag is Root root) { int index = roots.Items.IndexOf(root); if (index >= 0) roots.SetItemChecked(index, driveGrid.Rows[e.RowIndex].Cells[0].Value is true); } };
        driveArea.Controls.Add(driveGrid, 0, 1); page.Controls.Add(Theme.Card(driveArea, 0), 0, 2);
        var output = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1 }; output.RowStyles.Add(new(SizeType.Percent, 100)); output.ColumnStyles.Add(new(SizeType.Percent, 100)); output.ColumnStyles.Add(new(SizeType.Absolute, 166)); output.ColumnStyles.Add(new(SizeType.Absolute, 125)); database.PlaceholderText = "Evidence database path"; output.Controls.Add(database, 0, 0); browse.Dock = DockStyle.Fill; add.Dock = DockStyle.Fill; output.Controls.Add(browse, 1, 0); output.Controls.Add(add, 2, 0); page.Controls.Add(output, 0, 3);
        var performance = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 5, RowCount = 2 }; performance.RowStyles.Add(new(SizeType.Absolute, 26)); performance.RowStyles.Add(new(SizeType.Percent, 100));
        performance.Controls.Add(Theme.Label("PERFORMANCE   ·   Quiet to Maximum   ·   Resource budget, adjustable during a scan", true), 0, 0); performance.SetColumnSpan(performance.GetControlFromPosition(0, 0)!, 5);
        foreach (int width in new[] { 64, 55, 0, 55, 64 }) performance.ColumnStyles.Add(width == 0 ? new(SizeType.Percent, 100) : new(SizeType.Absolute, width));
        throttle.AutoSize = false; throttle.TickStyle = TickStyle.None; int index = 0; foreach (int delta in new[] { -10, -1, 1, 10 }) { var button = Button(delta > 0 ? "+" + delta : delta.ToString()); stepButtons[delta] = button; button.Dock = DockStyle.Fill; button.Click += (_, _) => Step(delta); performance.Controls.Add(button, index < 2 ? index : index + 1, 1); index++; }
        performance.Controls.Add(throttle, 2, 1); page.Controls.Add(Theme.Card(performance), 0, 4); page.Controls.Add(behavior, 0, 5);
        var actions = Theme.Flow(); actions.Controls.AddRange([start, settings, LabelInline("GPU"), gpu, LabelInline("CPU backend · USN continuity checked before Quick")]); page.Controls.Add(actions, 0, 6);
        var live = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 }; live.ColumnStyles.Add(new(SizeType.Percent, 43)); live.ColumnStyles.Add(new(SizeType.Percent, 57)); live.RowStyles.Add(new(SizeType.Percent, 100)); live.Controls.Add(Theme.Card(previewSummary), 0, 0); live.Controls.Add(Theme.Card(previewGraph), 1, 0); page.Controls.Add(live, 0, 7); return page;
    }
    private Control BuildActiveScan()
    {
        var page = Page("Active Scan", "Live acquisition and resource instrumentation", 58, 28, 88, 46, 0, 78, 46, 32);
        scanHeading.Font = new("Segoe UI", 13, FontStyle.Bold); page.Controls.Add(scanHeading, 0, 1); page.Controls.Add(progressBar, 0, 2);
        var metrics = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 6, RowCount = 1 }; metrics.RowStyles.Add(new(SizeType.Percent, 100)); foreach (string name in new[] { "Processed", "Changed", "Added", "Deleted", "Unstable", "Errors" }) { metrics.ColumnStyles.Add(new(SizeType.Percent, 16.66f)); Label value = name == "Errors" ? new LinkLabel { Text = "Errors\n0", Dock = DockStyle.Fill, LinkColor = Theme.StatusColor("ERROR"), TextAlign = ContentAlignment.MiddleLeft, TabStop = true } : Theme.Label(name + "\n0"); value.Font = new("Segoe UI", 13, FontStyle.Bold); value.ForeColor = name is "Errors" ? Theme.StatusColor("ERROR") : name is "Unstable" ? Theme.StatusColor("UNSTABLE") : Theme.Text; if (name == "Errors") value.Click += async (_, _) => await OpenErrors(); scanMetrics[name] = value; metrics.Controls.Add(Theme.Card(value)); } page.Controls.Add(metrics, 0, 3); page.Controls.Add(scanFraction, 0, 4);
        var monitoring = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 }; monitoring.RowStyles.Add(new(SizeType.Absolute, 42)); monitoring.RowStyles.Add(new(SizeType.Percent, 100)); monitoring.RowStyles.Add(new(SizeType.Absolute, 36)); monitoring.RowStyles.Add(new(SizeType.Absolute, 36));
        var graphControls = Theme.Flow(); graphControls.Controls.Add(LabelInline("LIVE METRIC")); var metric = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 }; metric.Items.AddRange(["Throughput", "CPU", "Files/sec", "Queue depth"]); metric.SelectedIndex = 0; metric.SelectedIndexChanged += (_, _) => { graph.Metric = metric.Text; graph.Invalidate(); }; graphControls.Controls.Add(metric); monitoring.Controls.Add(graphControls, 0, 0); monitoring.Controls.Add(graph, 0, 1); monitoring.Controls.Add(rates, 0, 2); monitoring.Controls.Add(activity, 0, 3); page.Controls.Add(Theme.Card(monitoring), 0, 5);
        var live = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 }; live.RowStyles.Add(new(SizeType.Absolute, 30)); live.RowStyles.Add(new(SizeType.Percent, 100)); live.Controls.Add(scanMemory, 0, 0); live.Controls.Add(liveThrottle, 0, 1); page.Controls.Add(live, 0, 6);
        var controls = Theme.Flow(); controls.Controls.AddRange([pause, cancel, inspect, status]); page.Controls.Add(controls, 0, 7); currentPath.Dock = DockStyle.Bottom; currentPath.Height = 32; currentPath.ForeColor = Theme.Muted; page.Controls.Add(currentPath, 0, 8); return page;
    }
    private Control BuildOverview()
    {
        var p = Page("Evidence Overview", "Volumes → scans → changes → file history → verification", 88, 38, 0, 38, 0, 48); p.Controls.Add(Theme.Card(overviewMetrics), 0, 1); p.Controls.Add(Theme.Label("RECENT SCANS", true), 0, 2);
        AddHistoryColumns(recentTable); p.Controls.Add(Theme.Card(recentTable, 0), 0, 3); p.Controls.Add(Theme.Label("VOLUME STATUS · detected asynchronously", true), 0, 4);
        foreach (string name in new[] { "Drive", "Label", "Filesystem", "Capacity", "Usage", "Storage", "USN", "Baseline", "Last scan", "Root", "Errors" }) volumeTable.Columns.Add(name, name); volumeTable.Columns[1].Width = 160; p.Controls.Add(Theme.Card(volumeTable, 0), 0, 5);
        var actions = Theme.Flow(); var baseline = Theme.Button("Create baseline", true); baseline.Click += (_, _) => Navigate("New Scan"); var open = Theme.Button("Open database"); open.Click += async (_, _) => { Navigate("Database Explorer"); await explorer.ChooseDatabase(); await RefreshOverview(); };
        var recent = Theme.Button("Recent databases"); recent.Click += (_, _) => { var menu = new ContextMenuStrip { BackColor = Theme.Surface, ForeColor = Theme.Text }; foreach (string path in workspace.RecentDatabases) { var item = menu.Items.Add(path); item.Click += async (_, _) => { Navigate("Database Explorer"); await explorer.OpenDatabase(path); await RefreshOverview(); }; } if (menu.Items.Count == 0) menu.Items.Add("No recent evidence databases").Enabled = false; menu.Closed += (_, _) => menu.Dispose(); menu.Show(Cursor.Position); };
        actions.Controls.AddRange([baseline, open, recent]); p.Controls.Add(actions, 0, 6); recentTable.CellDoubleClick += async (_, e) => { if (e.RowIndex >= 0 && recentTable.Rows[e.RowIndex].Tag is ScanEntry scan) await OpenScan(scan); }; return p;
    }
    private static void AddHistoryColumns(DataGridView table)
    {
        foreach (string name in new[] { "Started UTC", "Scan ID", "Scope", "Mode", "Files", "Bytes read", "Changes", "Errors", "Duration", "Root", "Status" }) table.Columns.Add(name, name);
        table.Columns[0].Width = 175; table.Columns[2].Width = 220; table.Columns[9].Width = 160; table.Columns[10].Width = 120;
    }
    private Control BuildHistory()
    {
        var p = Page("Scan History", "Latest 500 scans in the current database · double-click to inspect", 48, 0); var tools = Theme.Flow(); tools.AutoScroll = true; var refresh = Theme.Button("Refresh"); tools.Controls.AddRange([historySearch, refresh, showHiddenScans]); p.Controls.Add(tools, 0, 1); AddHistoryColumns(historyTable); p.Controls.Add(Theme.Card(historyTable, 0), 0, 2);
        historySearch.TextChanged += (_, _) => FillVisibleHistory(); showHiddenScans.CheckedChanged += (_, _) => FillVisibleHistory(); refresh.Click += async (_, _) => await RefreshOverview();
        historyTable.CellDoubleClick += async (_, e) => { if (e.RowIndex >= 0 && historyTable.Rows[e.RowIndex].Tag is ScanEntry scan) await OpenScan(scan); };
        var menu = new ContextMenuStrip(); historyTable.ContextMenuStrip = menu; historyTable.CellMouseDown += (_, e) => { if (e.Button == MouseButtons.Right && e.RowIndex >= 0) historyTable.CurrentCell = historyTable.Rows[e.RowIndex].Cells[0]; };
        menu.Opening += (_, e) =>
        {
            menu.Items.Clear(); if (historyTable.CurrentRow?.Tag is not ScanEntry scan) { e.Cancel = true; return; }
            void Action(string caption, Action action) { var item = menu.Items.Add(caption); item.Click += (_, _) => action(); }
            Action("Open scan", async () => await OpenScan(scan)); Action("Open database", async () => { string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db); }); Action("Compare with…", () => { preferredBaseline = scan.Id; Navigate("Compare"); baselineScan.SelectedItem = baselineScan.Items.Cast<ScanEntry>().FirstOrDefault(s => s.Id == scan.Id); }); Action("Copy scan ID", () => Clipboard.SetText(scan.Id.ToString())); Action("Copy root", () => { if (scan.Root.Length > 0) Clipboard.SetText(scan.Root); }); Action("Scan details", () => ShowText("Scan #" + scan.Id, JsonSerializer.Serialize(scan, ScanOptions.Json)));
            Action("Export manifest", async () => await ExportScanManifest(scan)); Action("Verify cryptographic roots", async () => await VerifyRoots(scan.Id)); Action("Generate report", async () => { await OpenScan(scan); await explorer.Export(false, forcedFormat: "html"); });
            Action("Verify manifest file", async () => await VerifyManifestFile()); Action("Reveal database", () => { var start = new System.Diagnostics.ProcessStartInfo("explorer.exe") { UseShellExecute = true }; start.ArgumentList.Add("/select," + EvidencePath); System.Diagnostics.Process.Start(start)?.Dispose(); });
            bool hidden = workspace.HiddenScans.Any(s => s.ScanId == scan.Id && string.Equals(s.Database, EvidencePath, StringComparison.OrdinalIgnoreCase));
            Action(hidden ? "Restore history entry" : "Remove history entry", async () => { if (!hidden && MessageBox.Show(this, "Hide this entry from the scan catalog? The evidence database and observation history are retained.", "Remove history entry", MessageBoxButtons.YesNo) != DialogResult.Yes) return; string db = EvidencePath; workspace = workspace with { HiddenScans = hidden ? workspace.HiddenScans.Where(s => !(s.ScanId == scan.Id && string.Equals(s.Database, db, StringComparison.OrdinalIgnoreCase))).ToArray() : workspace.HiddenScans.Append(new(db, scan.Id)).TakeLast(2000).ToArray() }; FillVisibleHistory(); await SaveWorkspace(); });
        }; return p;
    }
    private Control BuildCompare()
    {
        var p = Page("Compare Scans", "Compare completed observations within the same evidence scope", 96, 96, 0); var choices = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = true }; choices.Controls.AddRange([LabelInline("Baseline"), baselineScan, LabelInline("Comparison"), comparisonScan]); p.Controls.Add(choices, 0, 1);
        var actions = Theme.Flow(); actions.AutoScroll = true; var run = Theme.Button("Compare", true); var stop = Theme.Button("Cancel comparison"); stop.Enabled = false; stop.Click += (_, _) => comparisonCancellation?.Cancel(); var show = Theme.Button("Open comparison records"); var cross = Theme.Button("Compare another database"); actions.Controls.AddRange([run, stop, show, cross]); p.Controls.Add(actions, 0, 2); p.Controls.Add(Theme.Card(comparisonSummary), 0, 3);
        run.Click += async (_, _) =>
        {
            if (baselineScan.SelectedItem is not ScanEntry old || comparisonScan.SelectedItem is not ScanEntry newer) return;
            using var cancellation = new CancellationTokenSource(); comparisonCancellation = cancellation;
            try { string db = EvidencePath; run.Enabled = false; stop.Enabled = true; comparisonSummary.Text = "Comparing evidence…"; var result = await Task.Run(() => new DatabaseQueryService(db).CompareScans(old.Id, newer.Id, cancellation.Token), cancellation.Token); if (!IsDisposed && db == EvidencePath) comparisonSummary.Text = string.Join("\n", result.Select(pair => $"{pair.Key.Replace('_', ' '),-22} {pair.Value:N0}")); }
            catch (Exception ex) { if (!IsDisposed) comparisonSummary.Text = cancellation.IsCancellationRequested ? "Comparison cancelled." : ex.Message; }
            finally { comparisonCancellation = null; if (!IsDisposed) { run.Enabled = true; stop.Enabled = false; } }
        };
        show.Click += async (_, _) => { if (baselineScan.SelectedItem is ScanEntry old && comparisonScan.SelectedItem is ScanEntry newer) { string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ScanId = newer.Id, BaselineScanId = old.Id }); } };
        cross.Click += (_, _) => compare.PerformClick(); return p;
    }
    private Control BuildReports()
    {
        var p = Page("Reports & Evidence Health", "Stream structured evidence with source, filters, scan and export provenance", 105, 90, 0);
        var reports = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = true };
        foreach (var spec in new[] { ("Scan summary / all records", (string?)null), ("Changes", "CHANGED"), ("Errors", "ERROR"), ("Unstable files", "UNSTABLE") })
        { var b = Theme.Button(spec.Item1); b.Click += async (_, _) => { string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ScanId = catalog.FirstOrDefault()?.Id, Status = spec.Item2 == "CHANGED" ? null : spec.Item2, ChangedOnly = spec.Item2 == "CHANGED" }); await explorer.Export(false); }; reports.Controls.Add(b); }
        var review = Theme.Button("Review set"); review.Click += async (_, _) => { string? set = DatabaseExplorer.Prompt("Review set report", "Review set name", ""); if (string.IsNullOrWhiteSpace(set)) return; string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ReviewSet = set }); await explorer.Export(false); }; reports.Controls.Add(review);
        var comparison = Theme.Button("Scan comparison"); comparison.Click += async (_, _) => { if (baselineScan.SelectedItem is not ScanEntry old || comparisonScan.SelectedItem is not ScanEntry newer) { Navigate("Compare"); return; } string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ScanId = newer.Id, BaselineScanId = old.Id }); await explorer.Export(false); }; reports.Controls.Add(comparison);
        var manifest = Theme.Button("Export manifest"); manifest.Click += (_, _) => export.PerformClick(); reports.Controls.Add(manifest); p.Controls.Add(reports, 0, 1);
        var checks = Theme.Flow(); checks.AutoScroll = true; var structure = Theme.Button("SQLite integrity check"); var rootsButton = Theme.Button("Verify cryptographic roots"); var health = Theme.Button("Database health"); var stop = Theme.Button("Cancel check"); stop.Click += (_, _) => evidenceCheckCancellation?.Cancel(); checks.Controls.AddRange([structure, rootsButton, health, stop]); p.Controls.Add(checks, 0, 2);
        structure.Click += async (_, _) => { string db = EvidencePath; await RunEvidenceCheck("SQLite structural integrity", token => new DatabaseQueryService(db).CheckSqliteIntegrity(token)); }; rootsButton.Click += async (_, _) => await VerifyRoots(null);
        health.Click += async (_, _) => { string db = EvidencePath; try { var result = await Task.Run(() => new DatabaseQueryService(db).GetHealth()); ShowText("Database health · checks are independent", JsonSerializer.Serialize(result, ScanOptions.Json)); } catch (Exception ex) { ShowText("Database health", ex.Message); } };
        var manifestCheck = Theme.Button("Verify manifest file"); manifestCheck.Click += async (_, _) => await VerifyManifestFile(); checks.Controls.Add(manifestCheck);
        p.Controls.Add(Theme.Card(Theme.Label("CSV · JSON · JSONL · HTML reports · signed manifest envelopes\n\nExports stream from a consistent SQLite snapshot. HTML and structured exports retain provenance.\n\nSQLite integrity checks validate database structure. Cryptographic verification validates stored inventory roots and signatures.\n\nAnalyst annotations are stored in <evidence>.review.db and are excluded from the original scan roots.\n\nDriveWitness by Jesse Lee Shelley · https://github.com/ultros/DriveWitness", true)), 0, 3); return p;
    }
    private Control BuildPerformance()
    {
        var p = Page("Performance", "CPU BLAKE3 is the trusted backend · GPU acceleration is optional", 132, 76, 0); p.Controls.Add(Theme.Card(hardware), 0, 1);
        var tools = Theme.Flow(); var custom = Theme.Button("Custom resource settings"); custom.Click += (_, _) => Advanced(); var benchmarkAction = Theme.Button("Run benchmark"); benchmarkAction.Click += async (_, _) => await RunBenchmark(); tools.Controls.AddRange([custom, benchmarkAction]); p.Controls.Add(tools, 0, 2);
        p.Controls.Add(Theme.Card(Theme.Label("Resource bands: Quiet 0–20 · Low 21–45 · Balanced 46–70 · Fast 71–90 · Maximum 91–100\n\nFile concurrency and large-file hashing are scheduled separately. Large files reserve the native pool.\nLowering the live resource budget drains existing work and changes future scheduling.\n\nGPU: Auto / Off / Force use CPU until a validated, faster accelerator is installed.\nDisk and GPU utilization: unavailable; DriveWitness does not fabricate these metrics.\n\nBenchmarks use bounded, read-only samples. Results include filesystem cache effects.\nSettings expose workers, native pool cap, large-file threshold and database batching.\nRestart applies native thread-pool cap changes.", true)), 0, 3); return p;
    }
    private Control BuildBenchmark()
    {
        var p = Page("Benchmark", "Measure a bounded read-only sample before changing resource settings", 48, 0); var tools = Theme.Flow(); tools.AutoScroll = true; var run = Theme.Button("Benchmark selected drive / folder", true); run.Click += async (_, _) => await RunBenchmark(); var cached = Theme.Button("Last benchmark"); cached.Click += (_, _) => ShowText("Last benchmark", options.BenchmarkCache?.GetRawText() ?? "No benchmark has been recorded."); var apply = Theme.Button("Apply recommendation"); apply.Click += async (_, _) => await ApplyBenchmarkRecommendation(); tools.Controls.AddRange([run, cached, apply]); p.Controls.Add(tools, 0, 1);
        p.Controls.Add(Theme.Card(Theme.Label("Select a drive or folder on New Scan, then run this benchmark.\n\nMeasures CPU BLAKE3, SHA-256, dual hashing, sequential reads, worker counts and SQLite throughput.\n\nThe result is saved with settings for inspection. Recommendations require review before applying.\nThe sample is capped at 16 files / 64 MiB and is not a whole-volume throughput guarantee.", true)), 0, 2); return p;
    }
    private Control BuildSettings()
    {
        var p = Page("Settings", "Collection, hashing, database, signing and anonymization preferences", 48, 0); var tools = Theme.Flow(); var advanced = Theme.Button("Scanning / Performance / Advanced"); advanced.Click += (_, _) => Advanced(); var reset = Theme.Button("Restore scan/resource defaults"); reset.Click += async (_, _) => { if (busy) { status.Text = "Wait for the collection to finish before restoring defaults."; return; } options = new(); budget = new(options); throttle.Value = 60; mode.SelectedItem = "Verify"; gpu.SelectedItem = "Auto"; ShowBudget(); try { await Task.Run(() => options.Save()); status.Text = "Defaults restored. Native thread-pool changes apply after restart."; } catch (Exception ex) { ShowText("Settings", ex.Message); } }; tools.Controls.AddRange([advanced, reset]); p.Controls.Add(tools, 0, 1);
        p.Controls.Add(Theme.Card(Theme.Label("Appearance: dark · native Segoe UI · DPI-aware layouts\n\nWorkspace remembers window bounds, last and recent databases, evidence columns, filters, scan mode and resource budget.\n\nAdvanced settings include USN optimization, optional network clock observations, commit policy, include/exclude globs, external HMAC keys and Ed25519 signing.\n\nSigning passwords remain in memory for this session. Trusted timestamping is not configured.\n\nLicense: free use and free sharing with attribution; resale or paid access requires the owner's separate written agreement.", true)), 0, 2); return p;
    }
    private void Navigate(string name)
    {
        if (!pages.TryGetValue(name, out var page)) return; currentPage = name; pageTitle.Text = name;
        pageHost.SuspendLayout(); foreach (var pair in pages) pair.Value.Visible = pair.Key == name; page.BringToFront(); pageHost.ResumeLayout();
        foreach (var pair in navigation) { pair.Value.BackColor = pair.Key == name ? Color.FromArgb(22, 52, 87) : Color.FromArgb(12, 20, 31); pair.Value.ForeColor = pair.Key == name ? Theme.Text : Theme.Muted; }
        if (selfTest == null && name is "Overview" or "Scan History" or "Compare") _ = RefreshOverview();
        if (name == "Capabilities" && capabilityData != null) capabilitiesText.Text = JsonSerializer.Serialize(capabilityData, ScanOptions.Json);
        if (name == "Database Explorer" && explorer.DatabasePath == null && catalog.Count > 0) _ = explorer.OpenDatabase(database.Text);
    }
    private async Task OpenScan(ScanEntry scan) { string db = EvidencePath; Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ScanId = scan.Id }); }
    private void FillVisibleHistory() => FillHistory(historyTable, catalog.Where(s => (showHiddenScans.Checked || !workspace.HiddenScans.Any(h => h.ScanId == s.Id && string.Equals(h.Database, EvidencePath, StringComparison.OrdinalIgnoreCase))) && (s.ToString() + s.Scope + s.Root).Contains(historySearch.Text, StringComparison.OrdinalIgnoreCase)));
    private async Task RefreshOverview()
    {
        if (refreshingOverview || closing) return; refreshingOverview = true; string db = EvidencePath;
        try
        {
            var loaded = await Task.Run(() => (Scans: File.Exists(db) ? new DatabaseQueryService(db).GetScans() : [], Verification: new ReviewStore(db).LastVerification())); if (closing || IsDisposed || db != EvidencePath) return;
            long? oldId = preferredBaseline ?? (baselineScan.SelectedItem as ScanEntry)?.Id, newId = (comparisonScan.SelectedItem as ScanEntry)?.Id;
            catalog = loaded.Scans; FillVisibleHistory(); FillHistory(recentTable, catalog.Take(8)); baselineScan.Items.Clear(); comparisonScan.Items.Clear(); foreach (var scan in catalog.Where(s => s.Status == "COMPLETED")) { baselineScan.Items.Add(scan); comparisonScan.Items.Add(scan); }
            if (comparisonScan.Items.Count > 0) comparisonScan.SelectedItem = comparisonScan.Items.Cast<ScanEntry>().FirstOrDefault(s => s.Id == newId) ?? comparisonScan.Items[0]; if (baselineScan.Items.Count > 0) baselineScan.SelectedItem = baselineScan.Items.Cast<ScanEntry>().FirstOrDefault(s => s.Id == oldId) ?? baselineScan.Items[Math.Min(1, baselineScan.Items.Count - 1)]; preferredBaseline = null;
            var latest = catalog.FirstOrDefault(s => s.Status == "COMPLETED"); overviewMetrics.Text = latest == null ? "NO BASELINE · Select a volume and create a baseline to begin tracking changes." : $"{detectedVolumes.Count} detected volumes · Last completed: {latest.Completed} · {latest.Mode}\n{SummaryCounts(latest.Summary)} · Last file verification: {loaded.Verification ?? "Not recorded"}\nScan #{latest.Id} · Root {Theme.Short(latest.Root)} · Database/root health: not checked this session";
            RefreshVolumes();
        }
        catch (Exception ex) { if (!IsDisposed) overviewMetrics.Text = "Evidence catalog: " + ex.Message; }
        finally { refreshingOverview = false; }
    }
    private static string SummaryCounts(string summary)
    {
        try { using var doc = JsonDocument.Parse(summary); long Count(string name) => doc.RootElement.TryGetProperty(name, out var value) && value.TryGetInt64(out long number) ? number : 0; return $"Changed {Count("modified") + Count("added") + Count("deleted") + Count("renamed"):N0} · Errors {Count("errors"):N0} · Unstable {Count("unstable"):N0}"; }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return "Summary unavailable"; }
    }
    private static void FillHistory(DataGridView grid, IEnumerable<ScanEntry> scans)
    {
        grid.Rows.Clear(); foreach (var scan in scans)
        {
            JsonDocument? summary = null; try { summary = JsonDocument.Parse(scan.Summary.Length == 0 ? "{}" : scan.Summary); } catch (JsonException) { }
            using var summaryLifetime = summary; string Get(string key) => summary?.RootElement.ValueKind == JsonValueKind.Object && summary.RootElement.TryGetProperty(key, out var v) ? v.ToString() : "—";
            string scope = scan.Scope;
            try { using var document = JsonDocument.Parse(scope); scope = string.Join("; ", document.RootElement.GetProperty("roots").EnumerateArray().Select(root => root.GetString())); } catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { }
            int row = grid.Rows.Add(scan.Started.Replace('T', ' ')[..Math.Min(19, scan.Started.Length)], scan.Id, scope, scan.Mode, Get("processed"), Get("bytes_read"), Get("modified"), Get("errors"), Get("elapsed_seconds") + " s", scan.Root.Length > 14 ? scan.Root[..10] + "…" + scan.Root[^4..] : scan.Root, scan.Status); grid.Rows[row].Tag = scan; grid.Rows[row].Cells[10].Style.ForeColor = Theme.StatusColor(scan.Status);
        }
    }
    private void RefreshVolumes()
    {
        volumeTable.Rows.Clear(); foreach (var volume in detectedVolumes)
        {
            var baseline = BaselineFor(volume.Path);
            volumeTable.Rows.Add(volume.Path, volume.Label, volume.Filesystem, Theme.Size(volume.Total), Theme.Size(volume.Total - volume.Free), volume.Storage, volume.Filesystem == "NTFS" ? "Check at scan" : "Unavailable", baseline == null ? "No volume baseline" : "Recorded · inspect policy", baseline?.Completed ?? "—", Theme.Short(baseline?.Root ?? "—"), baseline == null ? "—" : SummaryCounts(baseline.Summary));
        }
    }
    private void RefreshRootGrid()
    {
        driveGrid.Rows.Clear(); foreach (Root root in roots.Items)
        {
            var volume = root.Volume; bool hasBaseline = BaselineFor(root.Path) != null;
            int index = driveGrid.Rows.Add(roots.GetItemChecked(roots.Items.IndexOf(root)), volume?.Path ?? "Folder", volume?.Label ?? root.Display, volume?.Filesystem ?? "Check at scan", volume == null ? "—" : Theme.Size(volume.Total), volume == null ? "—" : Theme.Size(volume.Total - volume.Free), volume?.Storage ?? "Auto", volume?.Filesystem == "NTFS" ? "Check at scan" : volume == null ? "Check at scan" : "Unavailable", hasBaseline ? "Baseline recorded" : "No baseline"); driveGrid.Rows[index].Tag = root;
            if (volume?.Error != null) { driveGrid.Rows[index].ReadOnly = true; driveGrid.Rows[index].DefaultCellStyle.ForeColor = Theme.Muted; driveGrid.Rows[index].Cells[0].ToolTipText = volume.Error; }
        }
    }
    private ScanEntry? BaselineFor(string path) => catalog.FirstOrDefault(scan =>
    {
        if (scan.Status != "COMPLETED") return false;
        try { using var scope = JsonDocument.Parse(scan.Scope); return scope.RootElement.GetProperty("roots").EnumerateArray().Any(root => string.Equals(root.GetString()?.Replace('\\', '/').TrimEnd('/'), path.Replace('\\', '/').TrimEnd('/'), StringComparison.OrdinalIgnoreCase)); }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException) { return false; }
    });
    private void UpdateScanInstrumentation(ScanProgress p)
    {
        scanHeading.Text = $"{options.Mode.ToUpperInvariant()} SCAN · {p.Status} · {TimeSpan.FromSeconds(p.ElapsedSeconds):hh\\:mm\\:ss}";
        foreach (var pair in new[] { ("Processed", p.Processed), ("Changed", p.Modified), ("Added", p.Added), ("Deleted", p.Deleted), ("Unstable", p.Unstable), ("Errors", p.Errors) }) scanMetrics[pair.Item1].Text = pair.Item1 + "\n" + pair.Item2.ToString("N0");
        progressBar.Fraction = p.Status == "COMPLETED" ? 1 : p.Discovered == 0 ? 0 : Math.Min(1, p.Processed / (double)p.Discovered); progressBar.Invalidate();
        scanFraction.Text = $"{p.Processed:N0} processed / {p.Discovered:N0} discovered · {(p.Status == "SCANNING" ? "namespace enumeration may still be running" : p.Status.ToLowerInvariant())} · {p.Skipped:N0} skipped";
        persistentScan.Text = $"{(control?.IsPaused == true ? "Paused" : p.Status)} · {p.Processed:N0} files · {p.ReadMbPerSecond:N1} MiB/s · CPU {p.ProcessCpuPercent:N0}%";
        using var process = System.Diagnostics.Process.GetCurrentProcess(); scanMemory.Text = $"Process memory {Theme.Size(process.WorkingSet64)} · Disk utilization unavailable · GPU Off · Resource budget {throttle.Value} / 100";
        previewSummary.Text = $"{p.Status} · {options.Mode.ToUpperInvariant()}\n\n{p.Processed:N0} files processed\n{p.Modified:N0} changed · {p.Added:N0} added · {p.Deleted:N0} deleted\n{p.Unstable:N0} unstable · {p.Errors:N0} errors\n\n{p.ReadMbPerSecond:N1} MiB/s · {p.FilesPerSecond:N0} files/sec\nElapsed {TimeSpan.FromSeconds(p.ElapsedSeconds):hh\\:mm\\:ss}\n\nOpen Active Scan for resource controls and queue metrics.";
    }
    private async Task VerifyRoots(long? scan)
    { string db = EvidencePath; await RunEvidenceCheck("Cryptographic root verification", token => Integrity.VerifyDatabase(db, scanId: scan, token: token)); }
    private async Task RunEvidenceCheck(string title, Func<CancellationToken, object> action)
    {
        if (evidenceCheckCancellation != null) { status.Text = "An evidence check is already running."; return; }
        using var cancellation = new CancellationTokenSource(); evidenceCheckCancellation = cancellation; status.Text = title + "…";
        try { string result = await Task.Run(() => JsonSerializer.Serialize(action(cancellation.Token), ScanOptions.Json), cancellation.Token); ShowText(title, result); }
        catch (Exception ex) { if (!IsDisposed) { if (cancellation.IsCancellationRequested) status.Text = "Evidence check cancelled."; else ShowText(title, ex.Message); } }
        finally { evidenceCheckCancellation = null; }
    }
    private async Task ExportScanManifest(ScanEntry scan)
    {
        using var dialog = new SaveFileDialog { Filter = "JSON manifest|*.json", FileName = $"scan-{scan.Id}-manifest.json" }; if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string db = EvidencePath, output = dialog.FileName; try { await Task.Run(() => Integrity.ExportManifest(db, output, scan.Id)); if (!IsDisposed) status.Text = "Manifest exported"; } catch (Exception ex) { ShowText("Manifest export", ex.Message); }
    }
    private async Task VerifyManifestFile()
    {
        using var dialog = new OpenFileDialog { Title = "Verify an exported manifest signature", Filter = "JSON manifest|*.json" }; if (dialog.ShowDialog(this) != DialogResult.OK) return; string path = dialog.FileName;
        try { ShowText("Manifest signature · embedded key is not independently trusted", JsonSerializer.Serialize(await Task.Run(() => Integrity.VerifyManifestFile(path)), ScanOptions.Json)); } catch (Exception ex) { ShowText("Manifest verification", ex.Message); }
    }
    private async Task ApplyBenchmarkRecommendation()
    {
        if (busy) { status.Text = "Wait for collection to finish before applying recommendations."; return; }
        if (options.BenchmarkCache is not JsonElement cache) { status.Text = "Run a benchmark first."; return; }
        try { var recommendation = cache.GetProperty("recommendation"); var updated = (options with { Workers = recommendation.GetProperty("workers").GetInt32(), Blake3Threads = recommendation.GetProperty("blake3_threads").GetInt32(), LargeFileThreshold = recommendation.GetProperty("large_file_threshold").GetInt64(), Gpu = recommendation.GetProperty("gpu").GetString()! }).Validate(); await Task.Run(() => updated.Save()); options = updated; budget = new(options); gpu.SelectedItem = "Off"; ShowBudget(); status.Text = "Recommendation applied; restart for a changed native pool cap."; }
        catch (Exception ex) { ShowText("Benchmark recommendation", ex.Message); }
    }
    private void About()
    {
        using var stream = typeof(MainForm).Assembly.GetManifestResourceStream("DriveWitness.License"); using var reader = stream == null ? null : new StreamReader(stream);
        ShowText("About / License", "DriveWitness 3.1.1\r\nForensic Baseline & Integrity Monitor\r\n\r\nDriveWitness by Jesse Lee Shelley\r\nCopyright (c) 2026 Jesse Lee Shelley. All Rights Reserved.\r\nhttps://linkedin.com/in/jesse-shelley\r\nhttps://github.com/ultros/DriveWitness\r\n\r\n" + reader?.ReadToEnd());
    }
    private void CommandPalette()
    {
        using var dialog = new Form { Text = "DriveWitness · Command palette", ClientSize = new(560, 470), StartPosition = FormStartPosition.CenterParent, Font = Font, BackColor = Background, ForeColor = TextColor, KeyPreview = true };
        var input = new TextBox { Dock = DockStyle.Top, PlaceholderText = "Type a page or command…" }; var list = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false, BorderStyle = BorderStyle.None, ItemHeight = 28 }; dialog.Controls.Add(list); dialog.Controls.Add(input);
        string[] commands = pages.Keys.Concat(["Open Database", "Search Files", "Verify Database", "Verify Roots"]).ToArray(); void Fill() { list.Items.Clear(); list.Items.AddRange(commands.Where(c => c.Contains(input.Text, StringComparison.OrdinalIgnoreCase)).ToArray()); if (list.Items.Count > 0) list.SelectedIndex = 0; }
        async Task Execute()
        {
            string? command = list.SelectedItem as string; if (command == null) return; dialog.Close();
            if (command == "Open Database") { Navigate("Database Explorer"); await explorer.ChooseDatabase(); }
            else if (command == "Search Files") { Navigate("Database Explorer"); explorer.FocusSearch(); }
            else if (command == "Verify Roots") await VerifyRoots(null);
            else if (command == "Verify Database") { string db = EvidencePath; Navigate("Reports"); await RunEvidenceCheck("SQLite structural integrity", token => new DatabaseQueryService(db).CheckSqliteIntegrity(token)); }
            else Navigate(command);
        }
        input.TextChanged += (_, _) => Fill(); dialog.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Escape) dialog.Close(); else if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await Execute(); } else if (e.KeyCode == Keys.Down && list.SelectedIndex < list.Items.Count - 1) { e.SuppressKeyPress = true; list.SelectedIndex++; } else if (e.KeyCode == Keys.Up && list.SelectedIndex > 0) { e.SuppressKeyPress = true; list.SelectedIndex--; } }; list.DoubleClick += async (_, _) => await Execute(); Theme.Apply(dialog); Fill(); dialog.Shown += (_, _) => input.Focus(); dialog.ShowDialog(this);
    }
    private async Task RestoreWorkspace()
    {
        workspace = await Task.Run(() => WorkspaceState.Load()); if (closing) return;
        double ratio = DeviceDpi / (double)Math.Max(1, workspace.Dpi); ClientSize = new(Math.Clamp((int)(workspace.Width * ratio), 1000, 5000), Math.Clamp((int)(workspace.Height * ratio), 650, 3200));
        if (workspace.X != null && workspace.Y != null) { var bounds = new Rectangle(workspace.X.Value, workspace.Y.Value, Width, Height); if (Screen.AllScreens.Any(s => s.WorkingArea.IntersectsWith(bounds))) Location = bounds.Location; }
        ConstrainToScreen();
        WorkspaceState.Restore(historyTable, workspace.HistoryColumns, workspace.Dpi); explorer.RestoreColumns(workspace.Columns, workspace.Dpi);
        explorer.RestoreViews(workspace.SavedViews);
        bool exists = workspace.Database != null && await Task.Run(() => File.Exists(workspace.Database));
        if (exists) { database.Text = workspace.Database!; await explorer.OpenDatabase(database.Text, workspace.Filter); await RefreshOverview(); }
    }
    private async Task SaveWorkspace()
    {
        var bounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds; var size = WindowState == FormWindowState.Normal ? ClientSize : new Size(bounds.Width - (Width - ClientSize.Width), bounds.Height - (Height - ClientSize.Height)); var saved = workspace with { Width = size.Width, Height = size.Height, Dpi = DeviceDpi, X = bounds.X, Y = bounds.Y, Database = EvidencePath, Columns = explorer.Columns, HistoryColumns = WorkspaceState.Capture(historyTable), Filter = explorer.Query, Mode = mode.Text, Performance = throttle.Value };
        var scanSettings = options with { Mode = mode.Text.ToLowerInvariant(), Performance = throttle.Value, Gpu = gpu.Text.ToLowerInvariant() };
        try { await Task.Run(() => { saved.Save(); scanSettings.Save(); }); } catch (Exception) { /* Closing must still complete if the settings directory is unavailable. */ }
    }
    protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Theme.DarkTitle(this); }
    private void ConstrainToScreen()
    {
        var screen = Screen.FromControl(this).WorkingArea; int gap = 24;
        MinimumSize = new(Math.Min((int)(1200 * DeviceDpi / 96d), screen.Width - gap), Math.Min((int)(760 * DeviceDpi / 96d), screen.Height - gap));
        if (WindowState != FormWindowState.Normal) return;
        Size = new(Math.Min(Width, screen.Width - gap), Math.Min(Height, screen.Height - gap));
        Location = new(Math.Clamp(Left, screen.Left, screen.Right - Width), Math.Clamp(Top, screen.Top, screen.Bottom - Height));
    }
}

internal sealed class ScanProgressBar : Control
{
    internal double Fraction;
    internal ScanProgressBar() { DoubleBuffered = true; AccessibleName = "Processed fraction of discovered files"; }
    protected override void OnPaint(PaintEventArgs e)
    {
        using var track = new SolidBrush(Theme.Border); using var fill = new SolidBrush(Theme.Blue); int height = Math.Max(4, Height / 3); e.Graphics.FillRectangle(track, 0, 3, Width, height); e.Graphics.FillRectangle(fill, 0, 3, (float)(Width * Fraction), height);
    }
}
