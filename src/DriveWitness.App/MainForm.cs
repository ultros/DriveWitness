using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;

namespace DriveWitness.App;

internal sealed class MainForm : Form
{
    internal static readonly Color Background = Color.FromArgb(17, 22, 30), PanelColor = Color.FromArgb(25, 33, 45), TextColor = Color.FromArgb(226, 235, 246), Accent = Color.FromArgb(88, 210, 193);
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
    private bool closing, busy;
    private string include = "", exclude = "", anonymous = "", anonymousKey = "", signingKey = "", signingPassword = "";
    private readonly string? selfTest;
    private readonly Stopwatch heartbeat = Stopwatch.StartNew();
    private readonly Dictionary<int, Button> stepButtons = new();
    private double lastBeat, maximumBeat, startupMilliseconds;
    private int beats;
    private string? testDirectory;

    private sealed record Root(string Path, string Display) { public override string ToString() => Display; }

    public MainForm(string? selfTest)
    {
        this.selfTest = selfTest;
        Text = "DriveWitness · Windows 11"; ClientSize = new(1120, 860); MinimumSize = new(880, 760);
        StartPosition = FormStartPosition.CenterScreen; AutoScaleMode = AutoScaleMode.Dpi;
        Font = new("Segoe UI", 10); BackColor = Background; ForeColor = TextColor;
        if (selfTest != null) { ShowInTaskbar = false; Opacity = 0; }
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(24, 16, 24, 16), ColumnCount = 1, RowCount = 12 };
        foreach (float height in new float[] { 64, 132, 42, 40, 74, 38, 52, 80, 34, 34, 0, 48 }) layout.RowStyles.Add(height == 0 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.Absolute, height));
        Controls.Add(layout);
        var title = Label("DRIVEWITNESS\nCryptographic filesystem baseline · BLAKE3 + SHA-256"); title.Font = new("Segoe UI", 14, FontStyle.Bold); title.ForeColor = Accent; layout.Controls.Add(title, 0, 0);
        var drivePanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 }; drivePanel.ColumnStyles.Add(new(SizeType.Percent, 100)); drivePanel.ColumnStyles.Add(new(SizeType.Absolute, 155));
        drivePanel.Controls.Add(roots, 0, 0); var right = Flow(); right.FlowDirection = FlowDirection.TopDown; right.Controls.Add(add); right.Controls.Add(settings); drivePanel.Controls.Add(right, 1, 0); layout.Controls.Add(drivePanel, 0, 1);
        var selection = Flow(); selection.Controls.Add(LabelInline("Scan mode")); mode.Items.AddRange(["Verify", "Quick", "Forensic"]); mode.SelectedIndex = 0; selection.Controls.Add(mode); selection.Controls.Add(LabelInline("GPU")); gpu.Items.AddRange(["Auto", "Off", "Force"]); gpu.SelectedIndex = 0; selection.Controls.Add(gpu); selection.Controls.Add(benchmark); layout.Controls.Add(selection, 0, 2);
        var output = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 }; output.ColumnStyles.Add(new(SizeType.Percent, 100)); output.ColumnStyles.Add(new(SizeType.Absolute, 155)); output.Controls.Add(database, 0, 0); output.Controls.Add(browse, 1, 0); layout.Controls.Add(output, 0, 3);
        database.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "drive_witness_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss") + "_" + Guid.NewGuid().ToString("N")[..8] + ".db");
        var performance = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 5, RowCount = 2 };
        performance.RowStyles.Add(new(SizeType.Absolute, 24)); performance.RowStyles.Add(new(SizeType.Percent, 100)); throttle.AutoSize = false;
        foreach (int width in new[] { 76, 60, 0, 60, 76 }) performance.ColumnStyles.Add(width == 0 ? new(SizeType.Percent, 100) : new(SizeType.Absolute, width));
        Button minus10 = Button("-10"), minus1 = Button("-1"), plus1 = Button("+1"), plus10 = Button("+10");
        foreach (var button in new[] { minus10, minus1, plus1, plus10 }) { button.AutoSize = false; button.Dock = DockStyle.Fill; button.Padding = new(0); }
        stepButtons[-10] = minus10; stepButtons[-1] = minus1; stepButtons[1] = plus1; stepButtons[10] = plus10;
        performance.Controls.Add(Label("PERFORMANCE · Quiet ↔ Maximum · adjustable during a scan"), 0, 0); performance.SetColumnSpan(performance.GetControlFromPosition(0, 0)!, 5);
        performance.Controls.Add(minus10, 0, 1); performance.Controls.Add(minus1, 1, 1); performance.Controls.Add(throttle, 2, 1); performance.Controls.Add(plus1, 3, 1); performance.Controls.Add(plus10, 4, 1); layout.Controls.Add(performance, 0, 4);
        minus10.Click += (_, _) => Step(-10); minus1.Click += (_, _) => Step(-1); plus1.Click += (_, _) => Step(1); plus10.Click += (_, _) => Step(10);
        throttle.ValueChanged += (_, _) => { budget.Set(throttle.Value); ShowBudget(); };
        layout.Controls.Add(behavior, 0, 5); layout.Controls.Add(hardware, 0, 6); layout.Controls.Add(counters, 0, 7); layout.Controls.Add(rates, 0, 8); layout.Controls.Add(activity, 0, 9); layout.Controls.Add(graph, 0, 10);
        var actions = Flow(); actions.Controls.Add(start); actions.Controls.Add(pause); actions.Controls.Add(cancel); actions.Controls.Add(inspect); actions.Controls.Add(export); actions.Controls.Add(verify); actions.Controls.Add(compare); actions.Controls.Add(status); layout.Controls.Add(actions, 0, 11);
        currentPath.Dock = DockStyle.Bottom; currentPath.Height = 29; currentPath.Padding = new(24, 0, 24, 0); currentPath.AutoEllipsis = true; Controls.Add(currentPath);
        pause.Enabled = cancel.Enabled = false; Style(this);
        add.Click += (_, _) => { using var dialog = new FolderBrowserDialog { Description = "Choose a scan root", UseDescriptionForTitle = true }; if (dialog.ShowDialog(this) == DialogResult.OK) roots.Items.Add(new Root(dialog.SelectedPath, dialog.SelectedPath), true); };
        browse.Click += (_, _) => { using var dialog = new SaveFileDialog { Filter = "Evidence database (*.db)|*.db", FileName = Path.GetFileName(database.Text), OverwritePrompt = false }; if (dialog.ShowDialog(this) == DialogResult.OK) database.Text = dialog.FileName; };
        start.Click += async (_, _) => await StartScan();
        pause.Click += (_, _) => { if (control?.IsPaused == true) { control.Resume(); pause.Text = "Pause"; } else { control?.Pause(); pause.Text = "Resume"; } };
        cancel.Click += (_, _) => { control?.Cancel(); status.Text = "Cancelling…"; };
        settings.Click += (_, _) => Advanced();
        benchmark.Click += async (_, _) => await RunBenchmark();
        inspect.Click += async (_, _) => await Inspect();
        export.Click += async (_, _) => await Export();
        verify.Click += async (_, _) => { string db = database.Text; try { var result = await Task.Run(() => Integrity.VerifyDatabase(db)); ShowText("Stored evidence verification", JsonSerializer.Serialize(result, ScanOptions.Json)); } catch (Exception ex) { ShowText("Verification error", ex.Message); } };
        compare.Click += async (_, _) =>
        {
            using var dialog = new OpenFileDialog { Title = "Choose baseline; compare it with the database shown in the main window", Filter = "Evidence database (*.db)|*.db|All files|*.*" };
            if (dialog.ShowDialog(this) != DialogResult.OK) return; string baseline = dialog.FileName, newer = database.Text;
            try { var result = await Task.Run(() => Operations.Compare(baseline, newer)); ShowText("Baseline comparison", JsonSerializer.Serialize(result, ScanOptions.Json)); } catch (Exception ex) { ShowText("Comparison error", ex.Message); }
        };
        timer.Tick += (_, _) => TickProgress();
        FormClosing += OnClosing;
        Shown += async (_, _) =>
        {
            startupMilliseconds = Program.Startup.Elapsed.TotalMilliseconds; timer.Start();
            if (selfTest != null) { await SelfTest(); return; }
            await Discover();
        };
    }

    private static Label Label(string text) => new() { Text = text, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, ForeColor = TextColor };
    private static Label LabelInline(string text) => new() { Text = text, AutoSize = true, Padding = new(3, 8, 5, 0), ForeColor = TextColor };
    private static Button Button(string text) => new() { Text = text, AutoSize = true, Height = 34, MinimumSize = new(48, 32), FlatStyle = FlatStyle.Flat, Padding = new(5, 2, 5, 2), ForeColor = TextColor, BackColor = PanelColor };
    private static FlowLayoutPanel Flow() => new() { Dock = DockStyle.Fill, WrapContents = false, Padding = new(0, 2, 0, 0) };
    internal static void Style(Control control)
    {
        if (control is TextBox or ComboBox or CheckedListBox or TrackBar) { control.BackColor = PanelColor; control.ForeColor = TextColor; }
        foreach (Control child in control.Controls) Style(child);
    }
    private void Step(int delta) => throttle.Value = Math.Clamp(throttle.Value + delta, 0, 100);
    private void ShowBudget()
    { var b = budget.Snapshot(); behavior.Text = $"{b.Label} {b.Level} · {b.Workers} file workers · large-file CPU threads {(b.LargeThreads == 1 ? "1" : "up to " + b.LargeThreads)} · queue limit {b.QueueDepth} · {b.Storage} · CPU hashing"; }

    private async Task Discover()
    {
        try
        {
            var discovery = Task.Run(() => (ScanOptions.Load(), NativeWindows.Drives())); var capabilities = Task.Run(() => NativeWindows.CapabilitiesAsync());
            var (loaded, drives) = await discovery; if (closing) return;
            options = loaded; budget = new(options); throttle.Value = options.Performance; mode.SelectedItem = char.ToUpperInvariant(options.Mode[0]) + options.Mode[1..]; gpu.SelectedItem = char.ToUpperInvariant(options.Gpu[0]) + options.Gpu[1..];
            foreach (var drive in drives) roots.Items.Add(new Root(drive.Path, $"{drive.Path}  {drive.Filesystem}  {(drive.Total - drive.Free) / 1073741824d:N1} / {drive.Total / 1073741824d:N1} GiB  {drive.Storage}"));
            ShowBudget(); var hardwareInfo = await capabilities; if (closing) return;
            hardware.Text = $"CPU: {hardwareInfo.GetValueOrDefault("cpu_name")} · {Environment.ProcessorCount} logical processors\nGPU: detected through Windows CIM; no validated hash backend · journal availability checked per scan";
            if (hardwareInfo.GetValueOrDefault("hardware") is JsonElement hw && hw.TryGetProperty("gpu", out var adapters))
                hardware.Text = $"CPU: {hardwareInfo.GetValueOrDefault("cpu_name")} · {Environment.ProcessorCount} logical processors\nGPU: {string.Join(", ", adapters.EnumerateArray().Select(g => g.GetProperty("Name").GetString()))} · CPU hashing";
        }
        catch (Exception ex) { status.Text = "Discovery unavailable"; hardware.Text = ex.Message; }
    }
    private void SetBusy(bool value)
    {
        busy = value; start.Enabled = settings.Enabled = benchmark.Enabled = add.Enabled = browse.Enabled = roots.Enabled = database.Enabled = mode.Enabled = gpu.Enabled = !value;
        pause.Enabled = cancel.Enabled = value && control != null; pause.Text = "Pause";
    }
    private async Task<ScanResult?> StartScan()
    {
        if (busy) return null;
        string[] selected = roots.CheckedItems.Cast<Root>().Select(r => r.Path).ToArray();
        if (selected.Length == 0) { status.Text = "Select a drive or folder"; return null; }
        options = options with { Performance = throttle.Value, Mode = mode.Text.ToLowerInvariant(), Gpu = gpu.Text.ToLowerInvariant() };
        budget = new(options); control = new(); SetBusy(true); graph.Clear(); status.Text = "Starting…";
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
        ShowBudget(); graph.Add(progress);
    }

    private void Advanced()
    {
        using var dialog = new Form { Text = "DriveWitness · Advanced settings", ClientSize = new(680, 690), StartPosition = FormStartPosition.CenterParent, BackColor = Background, ForeColor = TextColor, Font = Font, MinimizeBox = false, MaximizeBox = false };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(20), AutoScroll = true }; layout.ColumnStyles.Add(new(SizeType.Absolute, 230)); layout.ColumnStyles.Add(new(SizeType.Percent, 100)); dialog.Controls.Add(layout);
        int row = 0;
        TextBox Field(string caption, string value, bool multiline = false, bool secret = false)
        {
            var box = new TextBox { Text = value, Dock = DockStyle.Fill, Multiline = multiline, Height = multiline ? 60 : 29, UseSystemPasswordChar = secret };
            layout.RowStyles.Add(new(SizeType.Absolute, multiline ? 70 : 38)); layout.Controls.Add(Label(caption), 0, row); layout.Controls.Add(box, 1, row++); return box;
        }
        var workers = Field("Workers (blank = adaptive)", options.Workers?.ToString() ?? "");
        var threads = Field("Native BLAKE3 thread cap*", options.Blake3Threads?.ToString() ?? "");
        var threshold = Field("Large-file threshold (MiB)", (options.LargeFileThreshold / 1048576).ToString());
        var batch = Field("Commit row threshold", options.DbBatchRows.ToString());
        var seconds = Field("Commit seconds", options.DbCommitSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var includeBox = Field("Include globs · one per line", include, true); var excludeBox = Field("Exclude globs · one per line", exclude, true);
        var anonymousBox = Field("Anonymize roots · one per line", anonymous, true); var anonKeyBox = Field("External HMAC key file", anonymousKey);
        var signBox = Field("Ed25519 PEM key file", signingKey); var passwordBox = Field("PEM password · session only", signingPassword, secret: true);
        var usn = new CheckBox { Text = "USN optimization", Checked = options.UsnEnabled, AutoSize = true }; var network = new CheckBox { Text = "Observe HTTPS clock", Checked = options.NetworkTime, AutoSize = true }; layout.Controls.Add(usn, 0, row); layout.Controls.Add(network, 1, row++);
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
        string? root = roots.CheckedItems.Cast<Root>().FirstOrDefault()?.Path;
        if (root == null) { status.Text = "Select a drive or folder first"; return; }
        SetBusy(true); status.Text = "Benchmarking…";
        try { var report = await Task.Run(() => Operations.Benchmark(root, options)); options = options with { BenchmarkCache = JsonSerializer.SerializeToElement(report, ScanOptions.Json) }; await Task.Run(() => options.Save()); ShowText("Performance benchmark · cached measurements", JsonSerializer.Serialize(report, ScanOptions.Json)); status.Text = "Benchmark complete"; }
        catch (Exception ex) { ShowText("Benchmark error", ex.Message); }
        finally { SetBusy(false); }
    }
    private async Task Inspect()
    {
        string path = database.Text;
        try
        {
            string text = await Task.Run(() =>
            {
                using var db = EvidenceDatabase.Open(path, true); using var command = db.CreateCommand(); command.CommandText = "SELECT category,path,message FROM dw_events WHERE scan_id=(SELECT MAX(id) FROM dw_scans) ORDER BY id LIMIT 1000";
                using var reader = command.ExecuteReader(); var lines = new List<string>(); while (reader.Read()) lines.Add($"{reader.GetString(0)}  {(reader.IsDBNull(1) ? "" : reader.GetString(1))}\r\n{(reader.IsDBNull(2) ? "" : reader.GetString(2))}"); return string.Join("\r\n\r\n", lines);
            }); ShowText("Latest scan events · first 1,000", text.Length == 0 ? "No recorded events." : text);
        }
        catch (Exception ex) { ShowText("Evidence error", ex.Message); }
    }
    private async Task Export()
    {
        using var dialog = new SaveFileDialog { Filter = "JSON manifest (*.json)|*.json", FileName = "manifest.json" }; if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string db = database.Text, output = dialog.FileName;
        try { await Task.Run(() => Integrity.ExportManifest(db, output)); status.Text = "Manifest exported"; }
        catch (Exception ex) { ShowText("Export error", ex.Message); }
    }
    private void ShowText(string title, string text)
    {
        using var dialog = new Form { Text = title, ClientSize = new(840, 540), StartPosition = FormStartPosition.CenterParent, BackColor = Background, Font = Font };
        dialog.Controls.Add(new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Text = text, BackColor = PanelColor, ForeColor = TextColor }); dialog.ShowDialog(this);
    }
    private async void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (closing) return;
        if (work != null)
        {
            e.Cancel = true; control?.Cancel(); status.Text = "Saving partial evidence…";
            try { await work; } catch (Exception) { }
            closing = true; timer.Stop(); Close();
        }
        else { closing = true; timer.Stop(); }
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
            throttle.Value = 60; stepButtons[-10].PerformClick(); if (throttle.Value != 50) throw new InvalidOperationException("Throttle -10 failed"); stepButtons[-1].PerformClick(); stepButtons[1].PerformClick(); stepButtons[10].PerformClick(); if (throttle.Value != 60) throw new InvalidOperationException("Throttle steps failed");
            throttle.Value = 100; options = options with { UsnEnabled = false }; hardware.Text = "Windows 11 · native WinForms · official BLAKE3 CPU backend\nGUI acceptance scan · no network requests";
            var result = await StartScan();
            Directory.CreateDirectory(Path.GetDirectoryName(selfTest!)!);
            string screenshot = Path.ChangeExtension(selfTest, ".png")!;
            using (var bitmap = new Bitmap(Width, Height)) { DrawToBitmap(bitmap, new(0, 0, Width, Height)); bitmap.Save(screenshot, System.Drawing.Imaging.ImageFormat.Png); }
            var report = new { valid = result?.Status == "COMPLETED" && result.Summary.Errors == 0 && beats > 5 && maximumBeat < 500, startup_to_shown_ms = startupMilliseconds, heartbeat_interval_ms = 20, maximum_heartbeat_gap_ms = maximumBeat, heartbeat_count = beats, throttle_buttons_passed = true, scan = result, screenshot };
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
}

internal sealed class PerformanceGraph : Control
{
    private readonly Queue<ScanProgress> history = new();
    private double lastTime;
    public PerformanceGraph() { DoubleBuffered = true; BackColor = MainForm.PanelColor; ForeColor = MainForm.TextColor; AccessibleName = "Rolling read throughput, files per second and process CPU"; }
    public void Clear() { history.Clear(); lastTime = 0; Invalidate(); }
    public void Add(ScanProgress progress) { if (progress.ElapsedSeconds <= lastTime) return; lastTime = progress.ElapsedSeconds; history.Enqueue(progress); while (history.Count > 100) history.Dequeue(); Invalidate(); }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); var data = history.ToArray();
        e.Graphics.DrawString("Read MiB/s     Files/s     Process CPU % · each line uses its own scale", Font, SystemBrushes.ControlLightLight, 10, 8);
        if (data.Length < 2) return;
        int top = 37, height = Math.Max(1, Height - top - 10), width = Math.Max(1, Width - 20);
        var series = new (Func<ScanProgress, double> Value, Color Color)[] { (p => p.ReadMbPerSecond, MainForm.Accent), (p => p.FilesPerSecond, Color.CornflowerBlue), (p => p.ProcessCpuPercent, Color.Orange) };
        foreach (var line in series)
        {
            double max = Math.Max(1, data.Max(line.Value)); using var pen = new Pen(line.Color, 1.7f);
            var points = data.Select((p, i) => new PointF(10 + width * i / (float)(data.Length - 1), top + height * (1 - (float)(line.Value(p) / max)))).ToArray(); e.Graphics.DrawLines(pen, points);
        }
    }
}
