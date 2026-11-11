using Sentinel.Core;

namespace Sentinel.Agent;

internal sealed class StartupWatchers : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly Action<SecurityEvent> _publish;
    public StartupWatchers(Action<SecurityEvent> publish) => _publish = publish;

    public int Start()
    {
        foreach (var path in AutoRunScanner.StartupFolders())
        {
            if (!Directory.Exists(path)) continue;
            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite
                };
                watcher.Created += (_, e) => Emit(e.FullPath, "Created");
                watcher.Changed += (_, e) => Emit(e.FullPath, "Changed");
                watcher.Renamed += (_, e) => Emit(e.FullPath, "Renamed");
                watcher.Deleted += (_, e) => Emit(e.FullPath, "Deleted");
                watcher.Error += (_, _) => _publish(new SecurityEvent
                {
                    Category = "Health", Title = "Startup folder watcher overflow/error",
                    Description = "Events may have been lost; verify startup folder manually."
                });
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch { /* permission differences */ }
        }
        return _watchers.Count;
    }

    private void Emit(string path, string action)
    {
        var evt = new SecurityEvent
        {
            Source = "FileSystemWatcher", Category = "File", Title = "Startup folder " + action,
            Attributes = new() { ["TargetFilename"] = path }
        };
        ThreatScorer.Apply(evt);
        _publish(evt);
    }
    public void Dispose() { foreach (var w in _watchers) w.Dispose(); _watchers.Clear(); }
}
