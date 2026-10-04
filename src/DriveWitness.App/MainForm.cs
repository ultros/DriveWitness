using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;

namespace DriveWitness.App;

internal sealed partial class MainForm : Form
{
    internal static readonly Color Background = Theme.Background, PanelColor = Theme.Surface, TextColor = Theme.Text, Accent = Theme.Blue;
    private readonly CheckedListBox roots = new() { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
    private readonly TextBox database = new() { Dock = DockStyle.Fill };
    private readonly ComboBox mode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 125 };
    private readonly ComboBox gpu = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
    private readonly TrackBar throttle = new() { Minimum = 0, Maximum = 100, Value = 60, TickFrequency = 10, Dock = DockStyle.Fill, Height = 45, AccessibleName = "Performance resource budget" };
    private readonly Label behavior = Label("Balanced 60 · hardware discovery pending");
    private readonly Label hardware = Label("Hardware: detecting…  GPU backend: CPU only");
    private readonly Label status = Label("Ready");
    private readonly Label currentPath = Label("Select drives or add a folder to begin.");
    private readonly Label counters = Label("Discovered 0    Processed 0    Added 0    Changed 0    Deleted 0    Renamed 0\nErrors 0    Unstable 0    Skipped 0");
    private readonly Label rates = Label("Read 0 MiB/s    0 files/s    Process CPU 0%    Elapsed 00:00:00");
    private readonly Label activity = Label("Hash queue 0    DB queue 0    SHA-256 files 0");
    private readonly Button start = Button("Start scan"), pause = Button("Pause"), cancel = Button("Cancel"), settings = Button("Settings / Advanced"), benchmark = Button("Benchmark"), inspect = Button("Inspect events"), export = Button("Export manifest"), verify = Button("Verify evidence"), compare = Button("Compare"), add = Button("Add folder"), browse = Button("Choose database");
    private readonly PerformanceGraph graph = new() { Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 250 };
    private ScanOptions options = new();
    private ResourceBudget budget = new(new());
    private Scanner? scanner;
    private ScanControl? control;
    private Task? work;
    private bool closing, busy, closeRequested;
    private string include = "", exclude = "", anonymous = "", anonymousKey = "", signingKey = "", signingPassword = "";
    private readonly string? selfTest;
    private readonly string? initialDatabase;
    private readonly bool explorerTest;
    private readonly Stopwatch heartbeat = Stopwatch.StartNew();
    private readonly Dictionary<int, Button> stepButtons = new();
    private double lastBeat, maximumBeat, startupMilliseconds;
    private int beats;
    private string? testDirectory;

    private sealed record Root(string Path, string Display, VolumeInfo? Volume = null) { public override string ToString() => Display; }

    public MainForm(string? selfTest, string? initialDatabase = null, bool explorerTest = false)
    {
        this.selfTest = selfTest;
        this.initialDatabase = initialDatabase;
        this.explorerTest = explorerTest;
        BuildShell();
        database.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "drive_witness_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + "_" + Guid.NewGuid().ToString("N")[..8] + ".db");
        pause.Enabled = cancel.Enabled = start.Enabled = settings.Enabled = false;
        throttle.ValueChanged += (_, _) => { budget.Set(throttle.Value); ShowBudget(); };
        Style(this);
        add.Click += (_, _) => { using var dialog = new FolderBrowserDialog { Description = "Choose a scan root", UseDescriptionForTitle = true }; if (dialog.ShowDialog(this) == DialogResult.OK) { roots.Items.Add(new Root(dialog.SelectedPath, dialog.SelectedPath), true); RefreshRootGrid(); } };
        browse.Click += (_, _) => { using var dialog = new SaveFileDialog { Filter = "Evidence database (*.db)|*.db", FileName = Path.GetFileName(database.Text), OverwritePrompt = false }; if (dialog.ShowDialog(this) == DialogResult.OK) database.Text = dialog.FileName; };
        start.Click += async (_, _) => await StartScan();
        pause.Click += (_, _) => TogglePause();
        cancel.Click += (_, _) => { control?.Cancel(); status.Text = "Cancelling…"; };
        settings.Click += (_, _) => Advanced();
        benchmark.Click += async (_, _) => await RunBenchmark();
        inspect.Click += async (_, _) => await Inspect();
        export.Click += async (_, _) => await Export();
        verify.Click += async (_, _) => { string db = database.Text; try { var result = await Task.Run(() => Integrity.VerifyDatabase(db)); ShowText("Stored evidence verification", JsonSerializer.Serialize(result, ScanOptions.Json)); } catch (Exception ex) { ShowText("Verification error", ex.Message); } };
        compare.Click += async (_, _) =>
        {
            using var dialog = new OpenFileDialog { Title = "Choose baseline; compare it with the database shown in the main window", Filter = "Evidence database (*.db)|*.db|All files|*.*" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return; string baseline = dialog.FileName, newer = EvidencePath;
            try { var result = await Task.Run(() => Operations.Compare(baseline, newer)); ShowText("Baseline comparison", JsonSerializer.Serialize(result, ScanOptions.Json)); } catch (Exception ex) { ShowText("Comparison error", ex.Message); }
        };
        timer.Tick += (_, _) => TickProgress();
        FormClosing += OnClosing;
        Shown += async (_, _) =>
        {
            ConstrainToScreen();
            startupMilliseconds = Program.Startup.Elapsed.TotalMilliseconds; timer.Start();
            if (selfTest != null) { if (explorerTest) await ExplorerSelfTest(); else await SelfTest(); return; }
            if (initialDatabase == null) await RestoreWorkspace();
            else { Navigate("Database Explorer"); await explorer.OpenDatabase(initialDatabase); }
            await Discover();
        };
    }

    private static Label Label(string text) => new() { Text = text, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, ForeColor = TextColor };
    private static Label LabelInline(string text) => new() { Text = text, AutoSize = true, Padding = new(3, 8, 5, 0), ForeColor = TextColor };
    private static Button Button(string text) => Theme.Button(text);
    private static FlowLayoutPanel Flow() => new() { Dock = DockStyle.Fill, WrapContents = false, Padding = new(0, 2, 0, 0) };
    internal static void Style(Control control)
    {
        if (control is TextBox or ComboBox or CheckedListBox or TrackBar) { control.BackColor = PanelColor; control.ForeColor = TextColor; }
        foreach (Control child in control.Controls) Style(child);
    }
    private void Step(int delta) => throttle.Value = Math.Clamp(throttle.Value + delta, 0, 100);
    private void ShowBudget()
    { var b = budget.Snapshot(); behavior.Text = $"{b.Label} {b.Level} · {b.Workers} file workers · large-file CPU threads {(b.LargeThreads == 1 ? "1" : "up to " + b.LargeThreads)} · queue {b.QueueDepth} · DB batch {b.DatabaseBatchRows} · {b.Storage} · CPU hashing"; }

    private async Task Discover()
    {
        try
        {
            var discovery = Task.Run(() => { ScanOptions loaded; try { loaded = ScanOptions.Load(); } catch (Exception ex) when (ex is IOException or JsonException or ArgumentException or UnauthorizedAccessException) { loaded = new(); } return (loaded, NativeWindows.Drives()); }); var capabilities = Task.Run(() => NativeWindows.CapabilitiesAsync());
            var (loaded, drives) = await discovery; if (closing) return;
            options = loaded; budget = new(options); throttle.Value = options.Performance; mode.SelectedItem = char.ToUpperInvariant(options.Mode[0]) + options.Mode[1..]; gpu.SelectedItem = char.ToUpperInvariant(options.Gpu[0]) + options.Gpu[1..]; if (!busy) start.Enabled = settings.Enabled = true;
            foreach (var drive in drives) roots.Items.Add(new Root(drive.Path, $"{drive.Path}   {drive.Label}", drive));
            detectedVolumes = drives; RefreshVolumes();
            RefreshRootGrid();
            ShowBudget(); var hardwareInfo = await capabilities; if (closing) return;
            hardware.Text = $"CPU: {hardwareInfo.GetValueOrDefault("cpu_name")} · {Environment.ProcessorCount} logical processors\nGPU: detected through Windows CIM; no validated hash backend · journal availability checked per scan";
            capabilityData = hardwareInfo;
            if (hardwareInfo.GetValueOrDefault("hardware") is JsonElement hw && hw.TryGetProperty("gpu", out var adapters))
                hardware.Text = $"CPU: {hardwareInfo.GetValueOrDefault("cpu_name")} · {hw.GetProperty("physical_cores")} physical / {Environment.ProcessorCount} logical cores\nRAM: {Theme.Size(hw.GetProperty("ram_bytes").GetInt64())} · Storage/filesystem: selected volume on New Scan\nGPU: {string.Join(", ", adapters.EnumerateArray().Select(g => g.GetProperty("Name").GetString() + " · driver " + g.GetProperty("DriverVersion").GetString()))}\nBLAKE3: official Rust CPU · SHA-256: .NET CPU · GPU backend unavailable · VRAM detail in Capabilities";
        }
        catch (Exception ex) { if (!closing && !IsDisposed) { status.Text = "Discovery unavailable"; hardware.Text = ex.Message; start.Enabled = settings.Enabled = !busy; } }
    }
    private void SetBusy(bool value)
    {
        busy = value; start.Enabled = settings.Enabled = benchmark.Enabled = add.Enabled = browse.Enabled = roots.Enabled = database.Enabled = mode.Enabled = gpu.Enabled = !value;
        driveGrid.Enabled = !value;
        pause.Enabled = cancel.Enabled = value && control != null; pause.Text = "Pause";
        topPause.Enabled = pause.Enabled; topPause.Text = "Pause";
    }
    private void TogglePause()
    {
        if (control == null) return;
        if (control.IsPaused) { control.Resume(); pause.Text = topPause.Text = "Pause"; }
        else { control.Pause(); pause.Text = topPause.Text = "Resume"; }
    }
    private async Task<ScanResult?> StartScan()
    {
        if (busy) return null;
        string[] selected = roots.CheckedItems.Cast<Root>().Select(r => r.Path).ToArray();
        if (selected.Length == 0) { status.Text = "Select a drive or folder"; return null; }
        Navigate("Active Scan");
        options = options with { Performance = throttle.Value, Mode = mode.Text.ToLowerInvariant(), Gpu = gpu.Text.ToLowerInvariant() };
        budget = new(options); control = new(); SetBusy(true); graph.Clear(); previewGraph.Clear(); status.Text = "Starting…";
        Volatile.Write(ref scanner, null);
        string db = database.Text, anonymousText = anonymous, key = anonymousKey, includes = include, excludes = exclude, sign = signingKey, password = signingPassword;
        try
        {
            var task = Task.Run(() =>
            {
                var paths = new PathPolicy(selected, Lines(anonymousText), key.Length == 0 ? null : File.ReadAllBytes(key), Lines(includes), Lines(excludes));
                var engine = new Scanner(new(db, paths, options, sign.Length == 0 ? null : sign, password.Length == 0 ? null : password, IgnoredFiles: key.Length == 0 ? null : [key]), budget, control);
                Volatile.Write(ref scanner, engine); return engine.Run();
            });
            work = task; var result = await task; status.Text = result.Status; TickProgress();
            if (result.ManifestExportError != null && selfTest == null) ShowText("Evidence export warning", result.ManifestExportError);
            if (selfTest == null) await RefreshOverview();
            return result;
        }
        catch (Exception ex) { status.Text = "Failed"; if (selfTest == null) ShowText("Scan error", ex.Message); else throw; return null; }
        finally { SetBusy(false); control = null; work = null; }
    }
    private static string[] Lines(string text) => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    private void TickProgress()
    {
        double now = heartbeat.Elapsed.TotalMilliseconds;
        if (lastBeat > 0) maximumBeat = Math.Max(maximumBeat, now - lastBeat); lastBeat = now; beats++;
        var progress = Volatile.Read(ref scanner)?.Progress; if (progress == null) return;
        status.Text = control?.IsPaused == true ? "Paused" : progress.Status;
        currentPath.Text = progress.CurrentPath;
        counters.Text = $"Discovered {progress.Discovered:N0}    Processed {progress.Processed:N0}    Added {progress.Added:N0}    Changed {progress.Modified:N0}    Deleted {progress.Deleted:N0}    Renamed {progress.Renamed:N0}\nErrors {progress.Errors:N0}    Unstable {progress.Unstable:N0}    Skipped {progress.Skipped:N0}    Directories {progress.Directories:N0}";
        rates.Text = $"Read {progress.ReadMbPerSecond:N1} MiB/s    {progress.FilesPerSecond:N0} files/s    Process CPU {progress.ProcessCpuPercent:N1}%    Elapsed {TimeSpan.FromSeconds(progress.ElapsedSeconds):hh\\:mm\\:ss}    Read {progress.BytesRead / 1048576d:N1} MiB";
        activity.Text = $"Hash queue {progress.HashQueue}    DB queue {progress.DbQueue}    Active workers {progress.ActiveWorkers}    SHA-256 established {progress.Sha256Files:N0} files";
        ShowBudget(); graph.Add(progress); previewGraph.Add(progress); UpdateScanInstrumentation(progress);
    }

    private void Advanced()
    {
        if (busy) { status.Text = "Advanced settings are available after the current collection."; return; }
        using var dialog = new Form { Text = "DriveWitness · Advanced settings", ClientSize = new(680, 690), StartPosition = FormStartPosition.CenterParent, BackColor = Background, ForeColor = TextColor, Font = Font, MinimizeBox = false, MaximizeBox = false };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(20), AutoScroll = true }; layout.ColumnStyles.Add(new(SizeType.Absolute, 230)); layout.ColumnStyles.Add(new(SizeType.Percent, 100)); dialog.Controls.Add(layout);
        int row = 0;
        TextBox Field(string caption, string value, bool multiline = false, bool secret = false)
        {
            var box = new TextBox { Text = value, Dock = DockStyle.Fill, Multiline = multiline, Height = multiline ? 60 : 29, UseSystemPasswordChar = secret };
            layout.RowStyles.Add(new(SizeType.Absolute, multiline ? 70 : 38)); layout.Controls.Add(Label(caption), 0, row); layout.Controls.Add(box, 1, row++); return box;
        }
        var workers = Field("Worker cap (blank = adaptive)", options.Workers?.ToString() ?? "");
        var threads = Field("Native BLAKE3 thread cap*", options.Blake3Threads?.ToString() ?? "");
        var threshold = Field("Large-file threshold (MiB)", (options.LargeFileThreshold / 1048576).ToString());
        var batch = Field("Commit row threshold", options.DbBatchRows.ToString());
        var seconds = Field("Commit seconds", options.DbCommitSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var includeBox = Field("Include globs · one per line", include, true); var excludeBox = Field("Exclude globs · one per line", exclude, true);
        var anonymousBox = Field("Anonymize roots · one per line", anonymous, true); var anonKeyBox = Field("External HMAC key file", anonymousKey);
        var signBox = Field("Ed25519 PEM key file", signingKey); var passwordBox = Field("PEM password · session only", signingPassword, secret: true);
        var usn = new CheckBox { Text = "USN optimization", Checked = options.UsnEnabled, AutoSize = true }; var network = new CheckBox { Text = "Observe HTTPS clock (Cloudflare)", Checked = options.NetworkTime, AutoSize = true }; layout.Controls.Add(usn, 0, row); layout.Controls.Add(network, 1, row++);
        layout.Controls.Add(Label("*Restart applies a changed native pool cap. The live slider switches large-file hashing between serial and the capped pool."), 0, row); layout.SetColumnSpan(layout.GetControlFromPosition(0, row++)!, 2); layout.RowStyles.Add(new(SizeType.Absolute, 55));
        var save = Button("Save settings"); layout.Controls.Add(save, 1, row); Style(dialog);
        save.Click += async (_, _) =>
        {
            try
            {
                var updated = (options with { Performance = throttle.Value, Mode = mode.Text.ToLowerInvariant(), Gpu = gpu.Text.ToLowerInvariant(), Workers = workers.Text.Length == 0 ? null : int.Parse(workers.Text), Blake3Threads = threads.Text.Length == 0 ? null : int.Parse(threads.Text), LargeFileThreshold = long.Parse(threshold.Text) * 1048576,
                    DbBatchRows = int.Parse(batch.Text), DbCommitSeconds = double.Parse(seconds.Text, System.Globalization.CultureInfo.InvariantCulture), UsnEnabled = usn.Checked, NetworkTime = network.Checked }).Validate();
                save.Enabled = false; await Task.Run(() => updated.Save()); options = updated; budget = new(options); budget.Set(throttle.Value);
                include = includeBox.Text; exclude = excludeBox.Text; anonymous = anonymousBox.Text; anonymousKey = anonKeyBox.Text; signingKey = signBox.Text; signingPassword = passwordBox.Text;
                ShowBudget(); dialog.Close();
            }
            catch (Exception ex) { save.Enabled = true; MessageBox.Show(dialog, ex.Message, "Settings error"); }
        };
        dialog.ShowDialog(this);
    }
    private async Task RunBenchmark()
    {
        if (busy) { status.Text = "A collection or benchmark is already running."; return; }
        string? root = roots.CheckedItems.Cast<Root>().FirstOrDefault()?.Path;
        if (root == null) { status.Text = "Select a drive or folder first"; return; }
        SetBusy(true); status.Text = "Benchmarking…";
        try { var report = await Task.Run(() => Operations.Benchmark(root, options)); options = options with { BenchmarkCache = JsonSerializer.SerializeToElement(report, ScanOptions.Json) }; await Task.Run(() => options.Save()); ShowText("Performance benchmark · cached measurements", JsonSerializer.Serialize(report, ScanOptions.Json)); status.Text = "Benchmark complete"; }
        catch (Exception ex) { ShowText("Benchmark error", ex.Message); }
        finally { SetBusy(false); }
    }
    private async Task Inspect()
    {
        string db = database.Text;
        try { var events = await Task.Run(() => new DatabaseQueryService(db).GetEvents()); ShowText("Latest scan events · first 1,000", events.Count == 0 ? "No events are recorded for this scan." : JsonSerializer.Serialize(events, ScanOptions.Json)); }
        catch (Exception ex) { ShowText("Scan events", ex.Message); }
    }
    private async Task OpenErrors()
    {
        string db = database.Text;
        try { var scanId = await Task.Run(() => new DatabaseQueryService(db).GetScans().FirstOrDefault()?.Id); Navigate("Database Explorer"); await explorer.OpenDatabase(db, new() { ScanId = scanId, Status = "ERROR" }); }
        catch (Exception ex) { ShowText("File errors", ex.Message); }
    }
    private async Task Export()
    {
        using var dialog = new SaveFileDialog { Filter = "JSON manifest (*.json)|*.json", FileName = "manifest.json" }; if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string db = EvidencePath, output = dialog.FileName;
        try { await Task.Run(() => Integrity.ExportManifest(db, output)); status.Text = "Manifest exported"; }
        catch (Exception ex) { ShowText("Export error", ex.Message); }
    }
    private void ShowText(string title, string text)
    {
        if (closing || closeRequested || IsDisposed) return;
        using var dialog = new Form { Text = title, Icon = Icon, ClientSize = new(840, 540), StartPosition = FormStartPosition.CenterParent, BackColor = Background, Font = Font };
        dialog.Controls.Add(new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Text = text.ReplaceLineEndings("\r\n"), BackColor = PanelColor, ForeColor = TextColor }); dialog.ShowDialog(this);
    }
    private async void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (closing) return;
        if (selfTest != null) { closing = true; timer.Stop(); return; }
        if (closeRequested) { e.Cancel = true; return; } closeRequested = true;
        evidenceCheckCancellation?.Cancel(); comparisonCancellation?.Cancel();
        e.Cancel = true; control?.Cancel(); timer.Stop(); status.Text = "Saving workspace and partial evidence…";
        try { if (work != null) { try { await work; } catch (Exception) { /* StartScan has already presented and retained a failed collection. */ } } await SaveWorkspace(); }
        finally { closing = true; Close(); }
    }
    protected override void Dispose(bool disposing) { if (disposing) timer.Dispose(); base.Dispose(disposing); }

    private async Task SelfTest()
    {
        timer.Interval = 20;
        try
        {
            testDirectory = Path.Combine(Path.GetTempPath(), "DriveWitness-gui-" + Guid.NewGuid().ToString("N"));
            string root = Path.Combine(testDirectory, "data");
            await Task.Run(() => { Directory.CreateDirectory(root); byte[] data = new byte[65536]; new Random(0).NextBytes(data); for (int i = 0; i < 1000; i++) File.WriteAllBytes(Path.Combine(root, "file-" + i), data); });
            roots.Items.Add(new Root(root, "C:\\GUI acceptance sample · 1,000 × 64 KiB"), true); database.Text = Path.Combine(testDirectory, "gui.db");
            RefreshRootGrid();
            void Screenshot(string name)
            {
                string file = Path.Combine(Path.GetDirectoryName(selfTest!)!, name + ".png");
                using var bitmap = new Bitmap(Width, Height); DrawToBitmap(bitmap, new(0, 0, Width, Height)); bitmap.Save(file, System.Drawing.Imaging.ImageFormat.Png);
            }
            Directory.CreateDirectory(Path.GetDirectoryName(selfTest!)!); Screenshot("new-scan");
            var legalDocuments = LegalDocuments();
            bool legalDocumentsPassed = legalDocuments.Count == 5 && legalDocuments.Values.All(text => !string.IsNullOrWhiteSpace(text))
                && legalDocuments["Store Terms"].Contains("BioThreat Corporation", StringComparison.Ordinal)
                && legalDocuments["Third Party"].Contains("dotnet-THIRD-PARTY-NOTICES.txt", StringComparison.Ordinal)
                && legalDocuments["Third Party"].Contains("DriveWitness-prior-GPL-3.0.txt", StringComparison.Ordinal);
            foreach (string name in new[] { "Publisher", "Store Terms", "Privacy", "Third Party" })
            {
                using var legal = CreateLegalDialog(name); legal.Opacity = 0; legal.ShowInTaskbar = false; legal.Show(this); await Task.Delay(20);
                var tabs = (TabControl)legal.Controls[0]; var selectedLegal = tabs.SelectedTab; legalDocumentsPassed &= selectedLegal != null && selectedLegal.Text == name && selectedLegal.Controls[0].Text == legalDocuments[name];
                using var bitmap = new Bitmap(legal.Width, legal.Height); legal.DrawToBitmap(bitmap, new(0, 0, legal.Width, legal.Height)); bitmap.Save(Path.Combine(Path.GetDirectoryName(selfTest!)!, "legal-" + name.ToLowerInvariant().Replace(' ', '-') + ".png"), System.Drawing.Imaging.ImageFormat.Png); legal.Close();
            }
            if (!legalDocumentsPassed) throw new InvalidOperationException("Offline legal documents or legal tab selection are unavailable.");
            throttle.Value = 60; stepButtons[-10].PerformClick(); if (throttle.Value != 50) throw new InvalidOperationException("Throttle -10 failed"); stepButtons[-1].PerformClick(); stepButtons[1].PerformClick(); stepButtons[10].PerformClick(); if (throttle.Value != 60) throw new InvalidOperationException("Throttle steps failed");
            throttle.Value = 100; options = options with { UsnEnabled = false }; hardware.Text = "Windows 11 · native WinForms · official BLAKE3 CPU backend\nGUI acceptance scan · no network requests";
            bool liveBudgetPassed = false; int liveSteps = 0;
            using var budgetTimer = new System.Windows.Forms.Timer { Interval = 25 };
            budgetTimer.Tick += (_, _) =>
            {
                var engine = Volatile.Read(ref scanner); if (engine == null || !busy || liveSteps >= 2) return;
                liveThrottle.Value = liveSteps == 0 ? 90 : 100;
                liveBudgetPassed = engine.Budget.Snapshot().Level == liveThrottle.Value; liveSteps++;
            };
            budgetTimer.Start(); var result = await StartScan(); budgetTimer.Stop();
            double scanHeartbeat = maximumBeat; int scanBeats = beats; timer.Stop(); Screenshot("active-scan");
            await Task.Run(() => { File.WriteAllText(Path.Combine(root, "file-0"), "changed content"); File.WriteAllText(Path.Combine(root, "new-file"), "new content"); File.Delete(Path.Combine(root, "file-1")); });
            string sampleDatabase = database.Text; var sampleOptions = options with { Performance = 100, UsnEnabled = false };
            var nextScan = await Task.Run(() => new Scanner(new(sampleDatabase, new([root]), sampleOptions)).Run());
            await RefreshOverview();
            foreach (string page in new[] { "Overview", "Scan History", "Compare", "Reports", "Performance", "Settings" }) { Navigate(page); Screenshot(page.ToLowerInvariant().Replace(' ', '-')); }
            Navigate("Database Explorer"); var openTimer = Stopwatch.StartNew(); await explorer.OpenDatabase(database.Text); double explorerOpenMs = openTimer.Elapsed.TotalMilliseconds;
            await Task.Delay(100); Screenshot("database-explorer");
            bool reviewDraftPassed = await explorer.ReviewContextPreservesDraft(); await Task.Delay(50);
            bool fullDigestCopy = explorer.NativeCopyContainsFullDigests();
            bool boundedExplorer = explorer.VisibleRecordCount <= 256; int explorerRecords = explorer.VisibleRecordCount;
            await explorer.ApplyQuery(new() { ScanId = nextScan.ScanId, ChangedOnly = true }); await Task.Delay(50); Screenshot("changes");
            string alternateRoot = Path.Combine(testDirectory, "alternate"), alternateDatabase = Path.Combine(testDirectory, "alternate.db");
            await Task.Run(() => { Directory.CreateDirectory(alternateRoot); File.WriteAllText(Path.Combine(alternateRoot, "other-file"), "Alternate evidence"); new Scanner(new(alternateDatabase, new([alternateRoot]), sampleOptions)).Run(); });
            var firstOpen = explorer.OpenDatabase(sampleDatabase); var secondOpen = explorer.OpenDatabase(alternateDatabase); await Task.WhenAll(firstOpen, secondOpen); await Task.Delay(50);
            bool switchPassed = explorer.DatabasePath == alternateDatabase && explorer.VisibleRecordCount == 1 && explorer.InspectorMatchesDatabase;
            string invalidDatabase = Path.Combine(testDirectory, "unrelated.db"); await File.WriteAllTextAsync(invalidDatabase, "This is not evidence."); await explorer.OpenDatabase(invalidDatabase);
            switchPassed &= explorer.DatabasePath == null && explorer.VisibleRecordCount == 0 && explorer.InspectorMatchesDatabase;
            await explorer.OpenDatabase(sampleDatabase, new() { ScanId = nextScan.ScanId, ChangedOnly = true }); await Task.Delay(50);
            switchPassed &= explorer.VisibleRecordCount == 3 && explorer.InspectorMatchesDatabase;
            var layoutChecks = new List<object>(); float previousScale = 1;
            foreach (float scale in new[] { 1f, 1.25f, 1.5f, 2f })
            {
                if (scale != previousScale) Scale(new SizeF(scale / previousScale, scale / previousScale)); previousScale = scale; ConstrainToScreen();
                Navigate("Database Explorer"); await Task.Delay(30); bool usable = explorer.LayoutUsable; if (!usable) throw new InvalidOperationException($"Explorer layout is unusable at simulated control scale {scale}.");
                layoutChecks.Add(new { control_scale = scale, actual_device_dpi = DeviceDpi, window_width = Width, window_height = Height, explorer_usable = usable }); Screenshot("layout-scale-" + (scale * 100).ToString("F0"));
            }
            Scale(new SizeF(1 / previousScale, 1 / previousScale)); ClientSize = new(1200, 760); ConstrainToScreen(); await Task.Delay(30); if (!explorer.LayoutUsable) throw new InvalidOperationException("Explorer layout is unusable at the minimum window size."); Screenshot("layout-minimum");
            var persistence = new WorkspaceState { SavedViews = [new("Changed", database.Text, new() { ScanId = nextScan.ScanId, ChangedOnly = true })], HiddenScans = [new(database.Text, nextScan.ScanId)] }; string stateFile = Path.Combine(testDirectory, "workspace.json"); persistence.Save(stateFile); var restored = WorkspaceState.Load(stateFile);
            bool workspacePassed = restored.SavedViews.Length == 1 && restored.SavedViews[0].Query.ChangedOnly && restored.HiddenScans[0].ScanId == nextScan.ScanId;
            Directory.CreateDirectory(Path.GetDirectoryName(selfTest!)!);
            string screenshot = Path.ChangeExtension(selfTest, ".png")!;
            using (var bitmap = new Bitmap(Width, Height)) { DrawToBitmap(bitmap, new(0, 0, Width, Height)); bitmap.Save(screenshot, System.Drawing.Imaging.ImageFormat.Png); }
            var report = new { valid = result?.Status == "COMPLETED" && result.Summary.Errors == 0 && scanBeats > 5 && scanHeartbeat < 500 && boundedExplorer && explorer.VisibleRecordCount == 3 && liveBudgetPassed && liveSteps == 2 && fullDigestCopy && workspacePassed && switchPassed && reviewDraftPassed && legalDocumentsPassed,
                startup_to_shown_ms = startupMilliseconds, heartbeat_interval_ms = 20, maximum_heartbeat_gap_ms = scanHeartbeat, heartbeat_count = scanBeats,
                throttle_buttons_passed = true, live_budget_passed = liveBudgetPassed && liveSteps == 2, explorer_open_ms = explorerOpenMs, explorer_window_records = explorerRecords, filtered_changes = explorer.VisibleRecordCount,
                native_copy_full_digests = fullDigestCopy, review_context_preserves_draft = reviewDraftPassed, workspace_persistence = workspacePassed, database_switch_and_invalid_open = switchPassed, offline_legal_documents = legalDocumentsPassed, layout_checks = layoutChecks, layout_limitations = "Control scaling and window resizing on a 96-DPI monitor; physical mixed-DPI monitor transitions still require validation.", device_dpi = DeviceDpi, process_memory_bytes = Process.GetCurrentProcess().WorkingSet64, scan = result, screenshot };
            await Task.Run(() => File.WriteAllText(selfTest!, JsonSerializer.Serialize(report, ScanOptions.Json)));
            Environment.ExitCode = report.valid ? 0 : 1;
        }
        catch (Exception ex) { File.WriteAllText(selfTest!, JsonSerializer.Serialize(new { valid = false, error = ex.ToString() }, ScanOptions.Json)); Environment.ExitCode = 1; }
        finally
        {
            if (testDirectory != null)
            {
                string full = Path.GetFullPath(testDirectory);
                if (Path.GetDirectoryName(full) == Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) && Path.GetFileName(full).StartsWith("DriveWitness-gui-", StringComparison.Ordinal))
                    await Task.Run(() => Directory.Delete(full, true));
            }
            Close();
        }
    }
    private async Task ExplorerSelfTest()
    {
        timer.Interval = 20;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(selfTest!)!); Navigate("Database Explorer"); var openTime = Stopwatch.StartNew(); await explorer.OpenDatabase(initialDatabase!); openTime.Stop();
            int firstWindow = explorer.VisibleRecordCount; var health = await Task.Run(() => new DatabaseQueryService(initialDatabase!).GetHealth());
            var cancelledQuery = explorer.ApplyQuery(new() { Search = "no-match-during-gui-cancellation-test" }); await Task.Delay(100); var cancellation = Stopwatch.StartNew(); explorer.CancelPendingQuery(); await cancelledQuery; cancellation.Stop(); bool cancelled = explorer.LastQueryCancelled;
            await explorer.ApplyQuery(new()); await Task.Delay(100);
            string screenshot = Path.ChangeExtension(selfTest, ".png")!; using (var bitmap = new Bitmap(Width, Height)) { DrawToBitmap(bitmap, new(0, 0, Width, Height)); bitmap.Save(screenshot, System.Drawing.Imaging.ImageFormat.Png); }
            long observations = Convert.ToInt64(health["observations"]); var report = new { valid = firstWindow == 256 && explorer.VisibleRecordCount == 256 && observations >= 1_000_000 && cancelled && cancellation.Elapsed.TotalMilliseconds < 1000 && maximumBeat < 500,
                observations, database_bytes = health["bytes"], startup_to_shown_ms = startupMilliseconds, explorer_open_ms = openTime.Elapsed.TotalMilliseconds, records_in_window = explorer.VisibleRecordCount, cancellation_ms = cancellation.Elapsed.TotalMilliseconds,
                maximum_heartbeat_gap_ms = maximumBeat, process_memory_bytes = Process.GetCurrentProcess().WorkingSet64, device_dpi = DeviceDpi, writer_state = "Caller determines whether a concurrent writer is active.", screenshot };
            await File.WriteAllTextAsync(selfTest!, JsonSerializer.Serialize(report, ScanOptions.Json)); Environment.ExitCode = report.valid ? 0 : 1;
        }
        catch (Exception ex) { await File.WriteAllTextAsync(selfTest!, JsonSerializer.Serialize(new { valid = false, error = ex.ToString() }, ScanOptions.Json)); Environment.ExitCode = 1; }
        finally { Close(); }
    }
}

internal sealed class PerformanceGraph : Control
{
    internal string Metric = "Throughput";
    private readonly Queue<ScanProgress> history = new();
    private double lastTime;
    public PerformanceGraph() { DoubleBuffered = true; BackColor = MainForm.PanelColor; ForeColor = MainForm.TextColor; AccessibleName = "Rolling read throughput, files per second and process CPU"; }
    public void Clear() { history.Clear(); lastTime = 0; Invalidate(); }
    public void Add(ScanProgress progress) { if (progress.ElapsedSeconds <= lastTime) return; lastTime = progress.ElapsedSeconds; history.Enqueue(progress); while (history.Count > 100) history.Dequeue(); Invalidate(); }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); var data = history.ToArray();
        Func<ScanProgress, double> value = Metric switch { "CPU" => p => p.ProcessCpuPercent, "Files/sec" => p => p.FilesPerSecond, "Queue depth" => p => p.HashQueue + p.DbQueue, _ => p => p.ReadMbPerSecond };
        double max = Metric == "CPU" ? 100 : Math.Max(1, data.Select(value).DefaultIfEmpty(1).Max());
        using var text = new SolidBrush(Theme.Muted); e.Graphics.DrawString($"{Metric} · scale 0–{max:N0}" + (Metric == "Throughput" ? " MiB/s" : Metric == "CPU" ? "% (process)" : ""), Font, text, 10, 8);
        int top = 37, height = Math.Max(1, Height - top - 20), width = Math.Max(1, Width - 20);
        using var grid = new Pen(Theme.Border); for (int i = 0; i <= 4; i++) e.Graphics.DrawLine(grid, 10, top + height * i / 4, Width - 10, top + height * i / 4);
        if (data.Length < 2) { e.Graphics.DrawString("Measurements appear during collection", Font, text, 12, top + 10); return; }
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var pen = new Pen(Theme.Cyan, 2);
        var points = data.Select((p, i) => new PointF(10 + width * i / (float)(data.Length - 1), top + height * (1 - (float)(value(p) / max)))).ToArray();
        using var area = new System.Drawing.Drawing2D.GraphicsPath(); area.AddLines(points); area.AddLine(points[^1], new(Width - 10, top + height)); area.AddLine(new(Width - 10, top + height), new(10, top + height)); area.CloseFigure(); using var fill = new SolidBrush(Color.FromArgb(35, Theme.Blue)); e.Graphics.FillPath(fill, area); e.Graphics.DrawLines(pen, points);
    }
}
