using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace DriveWitness.Core;

public sealed record FileSnapshot(string VolumeSerial, string FileId, long Size, long CreatedNs,
    long ModifiedNs, long AccessedNs, uint Attributes, long ChangeTime, uint Links, bool Directory)
{
    public bool StableEquals(FileSnapshot other) => VolumeSerial == other.VolumeSerial && FileId == other.FileId &&
        Size == other.Size && ModifiedNs == other.ModifiedNs && CreatedNs == other.CreatedNs && ChangeTime == other.ChangeTime;
}

public sealed record VolumeInfo(string Path, string Label, string Filesystem, string Serial,
    long Total, long Free, string Storage, bool Local, string? Error = null);

public sealed record JournalCheckpoint(string Volume, string Serial, string JournalId,
    long FirstUsn, long NextUsn, long LowestValidUsn, string Filesystem = "NTFS");
public sealed record UsnRecord(string FileId, long Usn, uint Reason);

public static class NativeWindows
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct VersionInfo
    {
        public uint Size, Major, Minor, Build, Platform;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string ServicePack;
        public ushort ServicePackMajor, ServicePackMinor, SuiteMask;
        public byte ProductType, Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicInfo { public long Created, Accessed, Modified, Changed; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct StandardInfo { public long AllocationSize, Size; public uint Links; public byte DeletePending, Directory; }
    [StructLayout(LayoutKind.Sequential)] private struct IdInfo { public ulong Volume, Low, High; }

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)] private static extern int RtlGetVersion(ref VersionInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint security, uint disposition, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int type, out BasicInfo info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int type, out StandardInfo info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int type, out IdInfo info, uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumePathNameW(string file, StringBuilder path, uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetVolumeInformationW(string root, StringBuilder label, uint labelLength,
        out uint serial, out uint maxComponent, out uint flags, StringBuilder filesystem, uint fsLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeviceIoControl(SafeFileHandle handle, uint control, byte[]? input,
        uint inputLength, byte[] output, uint outputLength, out uint returned, nint overlapped);

    public static bool IsWindows11 => IsSupportedVersion();
    private static bool IsSupportedVersion()
    {
        if (!OperatingSystem.IsWindows()) return false;
        var info = new VersionInfo { Size = (uint)Marshal.SizeOf<VersionInfo>(), ServicePack = "" };
        return RtlGetVersion(ref info) == 0 && info.Major == 10 && info.Build >= 22000 && info.ProductType == 1;
    }
    public static void RequireWindows11()
    {
        if (!IsWindows11) throw new PlatformNotSupportedException("DriveWitness requires Windows 11 (build 22000+) on a workstation. Windows 10 and Windows Server are unsupported.");
    }
    public static string Extended(string path)
    {
        path = Path.GetFullPath(path);
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        return path.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + path[2..] : @"\\?\" + path;
    }
    private static SafeFileHandle Open(string path, uint access = 0, uint flags = 0x02200000)
    {
        var handle = CreateFileW(path, access, 7, 0, 3, flags, 0);
        if (handle.IsInvalid) { int code = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(code); }
        return handle;
    }
    public static FileStream OpenContent(string path)
    {
        // Read-only, shared with live writers/deleters, sequential hint, never follow a new reparse point.
        var handle = Open(Extended(path), 0x80000000, 0x08200000);
        try { return new FileStream(handle, FileAccess.Read, 1, false); }
        catch { handle.Dispose(); throw; }
    }
    public static string FinalPath(string path)
    {
        using var handle = Open(Extended(path));
        return FinalPath(handle);
    }
    public static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(512);
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (length >= buffer.Capacity)
        {
            if (length > 32768) throw new IOException("Resolved Windows path exceeds the supported limit.");
            buffer.EnsureCapacity((int)length + 1);
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (length >= buffer.Capacity) throw new IOException("Resolved path changed while its name was queried.");
        }
        string result = buffer.ToString();
        if (result.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) result = @"\\" + result[8..];
        else if (result.StartsWith(@"\\?\", StringComparison.Ordinal)) result = result[4..];
        return Path.TrimEndingDirectorySeparator(result);
    }
    public static FileSnapshot Snapshot(string path)
    {
        using var handle = Open(Extended(path));
        return Snapshot(handle);
    }
    public static FileSnapshot Snapshot(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, 0, out BasicInfo basic, (uint)Marshal.SizeOf<BasicInfo>()) ||
            !GetFileInformationByHandleEx(handle, 1, out StandardInfo standard, (uint)Marshal.SizeOf<StandardInfo>()) ||
            !GetFileInformationByHandleEx(handle, 18, out IdInfo id, (uint)Marshal.SizeOf<IdInfo>()))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        static long Ns(long ticks) => checked((ticks - 116444736000000000L) * 100);
        return new(id.Volume.ToString("x16"), id.High.ToString("x16") + id.Low.ToString("x16"), standard.Size,
            Ns(basic.Created), Ns(basic.Modified), Ns(basic.Accessed), basic.Attributes, basic.Changed, standard.Links, standard.Directory != 0);
    }
    public static byte[] Ioctl(SafeFileHandle handle, uint code, byte[]? input = null, int capacity = 65536)
    {
        byte[] output = new byte[capacity];
        if (!DeviceIoControl(handle, code, input, (uint)(input?.Length ?? 0), output, (uint)output.Length, out uint count, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return output[..checked((int)count)];
    }
    public static VolumeInfo Volume(string path)
    {
        var root = new StringBuilder(32768);
        if (!GetVolumePathNameW(Path.GetFullPath(path), root, (uint)root.Capacity)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var label = new StringBuilder(261); var fs = new StringBuilder(261);
        if (!GetVolumeInformationW(root.ToString(), label, 261, out uint serial, out _, out _, fs, 261)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var drive = new DriveInfo(root.ToString());
        bool local = drive.DriveType != DriveType.Network;
        string storage = local ? "unknown" : "remote";
        if (local && root.Length == 3)
        {
            try
            {
                using var handle = Open(@"\\.\" + root.ToString()[..2], flags: 0);
                byte[] query = new byte[12]; BinaryPrimitives.WriteUInt32LittleEndian(query, 7);
                byte[] penalty = Ioctl(handle, 0x002d1400, query, 128);
                if (penalty.Length >= 9) storage = penalty[8] != 0 ? "hdd" : "ssd";
                BinaryPrimitives.WriteUInt32LittleEndian(query, 0);
                byte[] device = Ioctl(handle, 0x002d1400, query, 1024);
                if (device.Length >= 32 && BinaryPrimitives.ReadUInt32LittleEndian(device.AsSpan(28)) == 17) storage = "nvme";
            }
            catch (Win32Exception) { /* Conservative fallback when capability access is unavailable. */ }
        }
        return new(root.ToString(), label.ToString(), fs.ToString(), serial.ToString("x8"), drive.TotalSize, drive.AvailableFreeSpace, storage, local);
    }
    public static IReadOnlyList<VolumeInfo> Drives()
    {
        var result = new List<VolumeInfo>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try { result.Add(Volume(drive.Name)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
            { result.Add(new(drive.Name, "", "unavailable", "", 0, 0, "unknown", true, ex.Message)); }
        }
        return result;
    }
    public static JournalCheckpoint QueryJournal(string path)
    {
        VolumeInfo info = Volume(path);
        if (info.Filesystem != "NTFS" || !info.Local || info.Path.Length != 3) throw new IOException("USN requires a local NTFS drive with an active journal.");
        using var handle = Open(@"\\.\" + info.Path[..2], 0x80000000, 0);
        byte[] data = Ioctl(handle, 0x000900f4);
        if (data.Length < 56) throw new InvalidDataException("Malformed USN journal response.");
        return new(info.Path, info.Serial, BinaryPrimitives.ReadUInt64LittleEndian(data).ToString(),
            BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(8)), BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(16)),
            BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(24)));
    }
    public static (bool Valid, string Reason) Continuity(JournalCheckpoint? previous, JournalCheckpoint current)
    {
        if (previous == null) return (false, "No previous journal checkpoint");
        if (previous.Serial != current.Serial) return (false, "Volume changed");
        if (previous.JournalId != current.JournalId) return (false, "Journal ID changed");
        if (previous.NextUsn < Math.Max(current.FirstUsn, current.LowestValidUsn)) return (false, "Journal records rolled off");
        if (previous.NextUsn > current.NextUsn) return (false, "Journal moved backwards");
        return (true, "Continuous");
    }
    public static IReadOnlyList<UsnRecord> ParseRecords(byte[] data, bool prefix = true)
    {
        int offset = prefix ? 8 : 0;
        if (data.Length < offset) throw new InvalidDataException("Truncated USN buffer.");
        var records = new List<UsnRecord>(); // One bounded IOCTL buffer, never the complete journal.
        while (offset < data.Length)
        {
            if (data.Length - offset < 8) throw new InvalidDataException("Truncated USN record.");
            int length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset)));
            ushort version = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 4));
            int minimum = version == 2 ? 60 : version == 3 ? 76 : 0;
            if (minimum == 0 || length < minimum || length % 8 != 0 || length > data.Length - offset) throw new InvalidDataException("Unsupported/malformed USN record.");
            int width = version == 2 ? 8 : 16;
            byte[] fileId = new byte[16]; data.AsSpan(offset + 8, width).CopyTo(fileId); Array.Reverse(fileId);
            long usn = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(offset + 8 + 2 * width));
            uint reason = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 24 + 2 * width));
            int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + minimum - 4));
            int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + minimum - 2));
            if (nameOffset < minimum || nameOffset + nameLength > length || nameLength % 2 != 0) throw new InvalidDataException("Malformed USN filename.");
            records.Add(new(Convert.ToHexStringLower(fileId), usn, reason));
            offset += length;
        }
        return records;
    }
    public static long FileUsn(string path)
    {
        using var handle = Open(Extended(path));
        var records = ParseRecords(Ioctl(handle, 0x000900eb, [2, 0, 3, 0]), false);
        if (records.Count != 1) throw new InvalidDataException("Malformed per-file USN response.");
        return records[0].Usn;
    }
    public static IEnumerable<UsnRecord> JournalChanges(JournalCheckpoint previous, JournalCheckpoint current, ScanControl control)
    {
        var continuity = Continuity(previous, current);
        if (!continuity.Valid) throw new InvalidDataException(continuity.Reason);
        using var handle = Open(@"\\.\" + current.Volume[..2], 0x80000000, 0);
        long checkpoint = previous.NextUsn;
        while (checkpoint < current.NextUsn)
        {
            control.Check();
            byte[] input = new byte[40];
            BinaryPrimitives.WriteInt64LittleEndian(input, checkpoint);
            BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8), uint.MaxValue);
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32), ulong.Parse(current.JournalId));
            byte[] data = Ioctl(handle, 0x000900bb, input, 1024 * 1024);
            if (data.Length < 8) throw new InvalidDataException("Truncated journal response.");
            long next = BinaryPrimitives.ReadInt64LittleEndian(data);
            if (next <= checkpoint) throw new InvalidDataException("USN reader made no progress.");
            foreach (var record in ParseRecords(data)) if (record.Usn < current.NextUsn) yield return record;
            checkpoint = next;
        }
        continuity = Continuity(previous, QueryJournal(current.Volume));
        if (!continuity.Valid) throw new InvalidDataException(continuity.Reason);
    }
    public static async Task<Dictionary<string, object?>> CapabilitiesAsync(CancellationToken token = default)
    {
        string cpu = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? "unknown";
        using (var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
            cpu = key?.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? cpu;
        var result = new Dictionary<string, object?> { ["version"] = "3.1.0", ["os"] = Environment.OSVersion.VersionString,
            ["windows_11"] = IsWindows11, ["cpu_name"] = cpu, ["cpu_logical"] = Environment.ProcessorCount,
            ["gpu_backend"] = "unavailable", ["blake3_backend"] = "Blake3.Native / official Rust BLAKE3",
            ["signing"] = "Ed25519", ["timestamp"] = "not configured", ["volumes"] = Drives() };
        try
        {
            using var process = new Process { StartInfo = new("powershell.exe") { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true } };
            foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command",
                "$cpu=Get-CimInstance Win32_Processor; $ram=Get-CimInstance Win32_ComputerSystem; $gpu=@(Get-CimInstance Win32_VideoController|Select-Object Name,AdapterRAM,DriverVersion); @{physical_cores=($cpu|Measure-Object NumberOfCores -Sum).Sum;ram_bytes=$ram.TotalPhysicalMemory;gpu=$gpu}|ConvertTo-Json -Depth 4 -Compress" }) process.StartInfo.ArgumentList.Add(argument);
            process.Start();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(8));
            Task<string> output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            Task<string> error = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
            catch { if (!process.HasExited) process.Kill(true); throw; }
            string json = await output.ConfigureAwait(false); await error.ConfigureAwait(false);
            if (process.ExitCode != 0) throw new IOException("Windows CIM hardware query failed.");
            using var document = JsonDocument.Parse(json);
            result["hardware"] = document.RootElement.Clone();
            result["vram_note"] = "CIM AdapterRAM is 32-bit and may underreport GPUs with more than 4 GiB.";
        }
        catch (Exception ex) when (ex is IOException or Win32Exception or JsonException or OperationCanceledException)
        { result["hardware_discovery_error"] = ex.Message; }
        return result;
    }
}
