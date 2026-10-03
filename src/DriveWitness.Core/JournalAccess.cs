namespace DriveWitness.Core;

public interface IJournalAccess
{
    JournalCheckpoint Query(string volume);
    IEnumerable<UsnRecord> Changes(JournalCheckpoint previous, JournalCheckpoint current, ScanControl control);
    long FileToken(string path);
}

public sealed class WindowsJournalAccess : IJournalAccess
{
    public JournalCheckpoint Query(string volume) => NativeWindows.QueryJournal(volume);
    public IEnumerable<UsnRecord> Changes(JournalCheckpoint previous, JournalCheckpoint current, ScanControl control) => NativeWindows.JournalChanges(previous, current, control);
    public long FileToken(string path) => NativeWindows.FileUsn(path);
}
