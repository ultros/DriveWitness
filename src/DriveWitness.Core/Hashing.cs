using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using Blake3;

namespace DriveWitness.Core;

public sealed class UnstableFileException(string message) : IOException(message);

public interface IHashBackend
{
    string Name { get; }
    string Version { get; }
    byte[] Digest(ReadOnlySpan<byte> input);
}

public static class CpuHashBackend
{
    private static readonly object Gate = new();
    private static bool initialized;
    public static int ThreadCap { get; private set; } = 1;
    public static void Initialize(ScanOptions options)
    {
        lock (Gate)
        {
            if (initialized) return;
            ThreadCap = Math.Min(Environment.ProcessorCount, options.Blake3Threads ?? 8);
            Environment.SetEnvironmentVariable("RAYON_NUM_THREADS", ThreadCap.ToString(System.Globalization.CultureInfo.InvariantCulture));
            // Validate the bundled official implementation before evidence collection.
            if (Convert.ToHexStringLower(Digest([])) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" ||
                Convert.ToHexStringLower(Digest("abc"u8)) != "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
                throw new CryptographicException("BLAKE3 backend failed its known-vector self-test.");
            initialized = true;
        }
    }
    public static byte[] Digest(ReadOnlySpan<byte> data)
    {
        using var hasher = Hasher.New(); hasher.Update(data); byte[] digest = new byte[32]; hasher.Finalize(digest); return digest;
    }
}

public sealed class ValidatedAccelerator
{
    private readonly IHashBackend? backend;
    public bool Eligible { get; private set; }
    public string? Error { get; private set; }
    public ValidatedAccelerator(IHashBackend? backend)
    {
        this.backend = backend;
        if (backend == null) return;
        try
        {
            var random = new Random(0);
            foreach (int size in new[] { 0, 1, 3, 64, 1024, 1025, 65536 })
            {
                byte[] sample = new byte[size]; random.NextBytes(sample);
                if (!backend.Digest(sample).AsSpan().SequenceEqual(CpuHashBackend.Digest(sample))) throw new CryptographicException("GPU digest validation failed.");
            }
            Eligible = true;
        }
        catch (Exception ex) { Error = ex.Message; }
    }
    public byte[] Digest(byte[] data)
    {
        byte[] expected = CpuHashBackend.Digest(data);
        if (Eligible)
        {
            try
            {
                if (!backend!.Digest(data).AsSpan().SequenceEqual(expected)) throw new CryptographicException("GPU runtime CPU cross-check failed.");
            }
            catch (Exception ex) { Eligible = false; Error = ex.Message; }
        }
        return expected;
    }
}

public sealed record HashResult(FileSnapshot Snapshot, byte[] Blake3, byte[] Sha256, string Method,
    string Status, string Sha256Provenance, long? Sha256OriginScan, long? ObjectUsn,
    Dictionary<string, double> Timings);

public static class FileHasher
{
    public static HashResult Hash(string path, FileRecord? previous, ScanOptions options, ResourceBudget budget,
        ScanControl control, Action<int>? bytesRead = null, Action? chunkRead = null)
    {
        CpuHashBackend.Initialize(options);
        var times = new Dictionary<string, double> { ["read"] = 0, ["blake3"] = 0, ["sha256"] = 0, ["metadata"] = 0 };
        byte[] buffer = ArrayPool<byte>.Shared.Rent(options.ChunkBytes);
        try
        {
            for (int attempt = 0; attempt <= options.UnstableRetries; attempt++)
            {
                try
                {
                    control.Check(); long started = Stopwatch.GetTimestamp();
                    using var stream = NativeWindows.OpenContent(path);
                    var before = NativeWindows.Snapshot(stream.SafeFileHandle);
                    if (before.Directory || (before.Attributes & 0x400) != 0) throw new IOException("File became a directory/reparse point; content not followed.");
                    if (PathPolicy.Canonical(NativeWindows.FinalPath(stream.SafeFileHandle)) != PathPolicy.Canonical(path))
                        throw new IOException("An ancestor reparse point or renamed directory redirected this path; content not followed.");
                    long? objectUsn = null;
                    if (before.Links > 1)
                        try { objectUsn = NativeWindows.FileUsn(path); } catch (Exception ex) when (ex is Win32Exception or IOException or InvalidDataException) { }
                    times["metadata"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                    bool dual = options.Mode == "forensic" || previous?.Blake3 == null || previous.Sha256 == null;
                    using var primary = Hasher.New();
                    using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    bool large = before.Size >= options.LargeFileThreshold;
                    while (true)
                    {
                        var current = budget.Snapshot(); control.Pace(current.DelayMilliseconds);
                        started = Stopwatch.GetTimestamp(); int count = stream.Read(buffer, 0, options.ChunkBytes);
                        times["read"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                        if (count == 0) break;
                        bytesRead?.Invoke(count); chunkRead?.Invoke();
                        started = Stopwatch.GetTimestamp();
                        if (large && current.LargeThreads > 1) primary.UpdateWithJoin(buffer.AsSpan(0, count));
                        else primary.Update(buffer.AsSpan(0, count));
                        times["blake3"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                        if (dual)
                        { started = Stopwatch.GetTimestamp(); sha.AppendData(buffer, 0, count); times["sha256"] += Stopwatch.GetElapsedTime(started).TotalSeconds; }
                    }
                    byte[] b3 = new byte[32]; primary.Finalize(b3);
                    bool changed = previous != null && !(previous.Blake3?.AsSpan().SequenceEqual(b3) ?? false);
                    if (!dual && changed)
                    {
                        stream.Position = 0;
                        while (true)
                        {
                            control.Pace(budget.Snapshot().DelayMilliseconds);
                            started = Stopwatch.GetTimestamp(); int count = stream.Read(buffer, 0, options.ChunkBytes);
                            times["read"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                            if (count == 0) break;
                            bytesRead?.Invoke(count); chunkRead?.Invoke();
                            started = Stopwatch.GetTimestamp(); sha.AppendData(buffer, 0, count);
                            times["sha256"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                        }
                    }
                    started = Stopwatch.GetTimestamp();
                    var after = NativeWindows.Snapshot(stream.SafeFileHandle);
                    var currentPath = NativeWindows.Snapshot(path);
                    if (!before.StableEquals(after) || !after.StableEquals(currentPath) ||
                        (objectUsn != null && objectUsn != NativeWindows.FileUsn(path))) throw new UnstableFileException("File changed during hashing.");
                    times["metadata"] += Stopwatch.GetElapsedTime(started).TotalSeconds;
                    bool recalculated = dual || changed;
                    return new(before, b3, recalculated ? sha.GetHashAndReset() : previous!.Sha256!,
                        dual ? "FULL_DUAL_HASH" : changed ? "BLAKE3_CHANGED_SHA256" : "FULL_BLAKE3",
                        previous == null ? "ADDED" : changed ? "MODIFIED" : "UNCHANGED",
                        recalculated ? "RECALCULATED" : "CARRIED_FORWARD", recalculated ? null : previous!.Sha256OriginScan, objectUsn, times);
                }
                catch (UnstableFileException) when (attempt < options.UnstableRetries) { }
            }
            throw new UnstableFileException("File remained unstable after retries.");
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }
}
