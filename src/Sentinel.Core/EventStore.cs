using System.Text;
using System.Text.Json;

namespace Sentinel.Core;

public static class EventStore
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private const long RotateAtBytes = 20L * 1024 * 1024;
    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelDFIR");
    public static string EventsPath => Path.Combine(DataDirectory, "events.jsonl");
    public static string SnapshotPath => Path.Combine(DataDirectory, "snapshot.json");

    public static async Task AppendAsync(SecurityEvent item, CancellationToken ct = default)
    {
        await Gate.WaitAsync(ct);
        try
        {
            Directory.CreateDirectory(DataDirectory);
            if (File.Exists(EventsPath) && new FileInfo(EventsPath).Length > RotateAtBytes)
            {
                var backup = Path.Combine(DataDirectory, $"events-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.jsonl");
                File.Move(EventsPath, backup); // preserve old evidence, never silently delete it
            }
            await using var stream = new FileStream(EventsPath, FileMode.Append,
                FileAccess.Write, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.Asynchronous);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            await writer.WriteLineAsync(JsonSerializer.Serialize(item).AsMemory(), ct);
        }
        finally { Gate.Release(); }
    }

    public static List<SecurityEvent> ReadLatest(int count = 500)
    {
        if (!File.Exists(EventsPath)) return [];
        try
        {
            using var stream = new FileStream(EventsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var max = Math.Min(stream.Length, 4L * 1024 * 1024);
            stream.Seek(-max, SeekOrigin.End);
            byte[] buffer = new byte[(int)max];
            int read = 0;
            while (read < buffer.Length)
            {
                var n = stream.Read(buffer, read, buffer.Length - read);
                if (n == 0) break;
                read += n;
            }
            var offset = 0;
            if (stream.Length > max)
            {
                while (offset < read && buffer[offset++] != (byte)'\n') { }
            }
            var text = Encoding.UTF8.GetString(buffer, offset, read - offset);
            var items = new Queue<SecurityEvent>();
            foreach (string line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var evt = JsonSerializer.Deserialize<SecurityEvent>(line);
                    if (evt is null) continue;
                    items.Enqueue(evt);
                    while (items.Count > count) items.Dequeue();
                }
                catch (JsonException) { /* partial entry on concurrent writer */ }
            }
            return items.Reverse().ToList();
        }
        catch (IOException) { return []; }
    }

    public static async Task WriteSnapshotAsync(MachineSnapshot snapshot, CancellationToken ct = default)
    {
        Directory.CreateDirectory(DataDirectory);
        var temp = Path.Combine(DataDirectory, $"snapshot-{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(snapshot), ct);
            File.Move(temp, SnapshotPath, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    public static MachineSnapshot? ReadSnapshot()
    {
        try { return File.Exists(SnapshotPath) ? JsonSerializer.Deserialize<MachineSnapshot>(File.ReadAllText(SnapshotPath)) : null; }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }
}
