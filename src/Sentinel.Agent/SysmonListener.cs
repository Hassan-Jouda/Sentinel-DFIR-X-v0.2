using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Sentinel.Core;

namespace Sentinel.Agent;

public sealed class SysmonListener : IDisposable
{
    private EventLogWatcher? _watcher;
    private readonly Action<SecurityEvent> _publish;
    private const string Channel = "Microsoft-Windows-Sysmon/Operational";

    public SysmonListener(Action<SecurityEvent> publish) => _publish = publish;
    public bool Start()
    {
        try
        {
            var ids = "EventID=1 or EventID=3 or EventID=5 or EventID=6 or EventID=8 or " +
                      "EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or " +
                      "EventID=15 or EventID=19 or EventID=20 or EventID=21 or EventID=22 or " +
                      "EventID=25 or EventID=26";
            _watcher = new EventLogWatcher(new EventLogQuery(Channel, PathType.LogName,
                $"*[System[({ids})]]"));
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            return true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            Dispose();
            return false;
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null || args.EventRecord is null) return;
        try
        {
            using var record = args.EventRecord;
            var xml = XDocument.Parse(record.ToXml());
            var a = xml.Descendants()
                .Where(n => n.Name.LocalName == "Data" && n.Attribute("Name") is not null)
                .GroupBy(n => (string)n.Attribute("Name")!)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
            int id = record.Id;
            string category = id switch
            {
                1 or 5 or 8 or 10 or 25 => "Process",
                3 or 22 => "Network", 11 or 15 or 26 => "File",
                12 or 13 or 14 or 19 or 20 or 21 => "Registry",
                _ => "System"
            };
            string title = id switch
            {
                1 => "Process created", 3 => "Process network connection", 5 => "Process terminated",
                8 => "Remote thread creation", 10 => "Process access",
                11 => "File created", 12 or 13 or 14 => "Registry change",
                19 or 20 or 21 => "WMI persistence-related event", 22 => "DNS query",
                25 => "Process tampering event", 26 => "File deleted", _ => $"Sysmon event {id}"
            };
            int? pid = a.TryGetValue("ProcessId", out var raw) && int.TryParse(raw, out var p) ? p : null;
            a.TryGetValue("ProcessGuid", out var guid);
            var evt = new SecurityEvent
            {
                Source = "Sysmon", EventId = id, Category = category, Title = title,
                TimestampUtc = record.TimeCreated is DateTime time
                    ? new DateTimeOffset(time.ToUniversalTime()) : DateTimeOffset.UtcNow,
                ProcessId = pid, ProcessGuid = guid, Attributes = a
            };
            ThreatScorer.Apply(evt);
            _publish(evt);
        }
        catch { /* A malformed event must not bring down the service. */ }
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        _watcher.EventRecordWritten -= OnEvent;
        _watcher.Dispose();
        _watcher = null;
    }
}
