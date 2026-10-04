using Microsoft.Data.Sqlite;

namespace DriveWitness.Core;

public sealed record AnalystReview(long ScanId, string Path, bool Flagged, bool Reviewed, string Note, string Set, string Created, string Modified, string Analyst);

/// <summary>Analyst edits are stored beside evidence, never inside dw_files or the evidence roots.</summary>
public sealed class ReviewStore(string evidenceDatabase)
{
    public string Path { get; } = System.IO.Path.GetFullPath(evidenceDatabase) + ".review.db";
    private SqliteConnection Open(bool create)
    {
        var db = EvidenceDatabase.Open(Path, !create);
        if (create)
        {
            using var c = db.CreateCommand(); c.CommandText = """
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS annotations(scan_id INTEGER,path TEXT,flagged INTEGER,reviewed INTEGER,note TEXT,review_set TEXT,created TEXT,modified TEXT,analyst TEXT,PRIMARY KEY(scan_id,path));
              CREATE TABLE IF NOT EXISTS verification_events(id INTEGER PRIMARY KEY,scan_id INTEGER,path TEXT,created TEXT,analyst TEXT,result TEXT);
              """; c.ExecuteNonQuery();
        }
        return db;
    }
    public AnalystReview? Get(FileRecord row)
    {
        if (!File.Exists(Path)) return null;
        using var db = Open(false); using var c = db.CreateCommand(); c.CommandText = "SELECT * FROM annotations WHERE scan_id=$id AND path=$path";
        c.Parameters.AddWithValue("$id", row.ScanId); c.Parameters.AddWithValue("$path", row.CanonicalPath);
        using var r = c.ExecuteReader(); return r.Read() ? new(r.GetInt64(0), r.GetString(1), r.GetBoolean(2), r.GetBoolean(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7), r.GetString(8)) : null;
    }
    public void Save(FileRecord row, bool flagged, bool reviewed, string note, string set)
    {
        if (note.Length > 100000 || set.Length > 200) throw new ArgumentException("Review note or set name exceeds its allowed length.");
        using var db = Open(true); using var c = db.CreateCommand();
        c.CommandText = """
          INSERT INTO annotations VALUES($id,$path,$flag,$review,$note,$set,$time,$time,$analyst)
          ON CONFLICT(scan_id,path) DO UPDATE SET flagged=excluded.flagged,reviewed=excluded.reviewed,note=excluded.note,review_set=excluded.review_set,modified=excluded.modified,analyst=excluded.analyst
          """;
        c.Parameters.AddWithValue("$id", row.ScanId); c.Parameters.AddWithValue("$path", row.CanonicalPath);
        c.Parameters.AddWithValue("$flag", flagged); c.Parameters.AddWithValue("$review", reviewed); c.Parameters.AddWithValue("$note", note); c.Parameters.AddWithValue("$set", set);
        c.Parameters.AddWithValue("$time", EvidenceDatabase.Utc()); c.Parameters.AddWithValue("$analyst", Environment.UserDomainName + "\\" + Environment.UserName); c.ExecuteNonQuery();
    }
    public void AppendVerification(FileRecord row, LiveComparison result)
    {
        using var db = Open(true); using var c = db.CreateCommand(); c.CommandText = "INSERT INTO verification_events(scan_id,path,created,analyst,result) VALUES($id,$path,$time,$analyst,$result)";
        c.Parameters.AddWithValue("$id", row.ScanId); c.Parameters.AddWithValue("$path", row.CanonicalPath); c.Parameters.AddWithValue("$time", EvidenceDatabase.Utc());
        c.Parameters.AddWithValue("$analyst", Environment.UserDomainName + "\\" + Environment.UserName); c.Parameters.AddWithValue("$result", System.Text.Json.JsonSerializer.Serialize(result, ScanOptions.Json)); c.ExecuteNonQuery();
    }
}
