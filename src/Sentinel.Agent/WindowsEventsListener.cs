using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Sentinel.Core;

namespace Sentinel.Agent;

public sealed class WindowsEventsListener : IDisposable
{
    private readonly List<EventLogWatcher> _watchers = [];
    private readonly Action<SecurityEvent> _publish;
    public WindowsEventsListener(Action<SecurityEvent> publish) => _publish = publish;

    public int Start()
    {
        Watch("System", "*[System[(EventID=7045)]]", "System", "Windows service installed");
        Watch("Microsoft-Windows-Windows Defender/Operational", "*[System[(EventID=1116 or EventID=1117)]]",
            "Defender", "Microsoft Defender detection/action");
        Watch("Microsoft-Windows-TaskScheduler/Operational", "*[System[(EventID=106 or EventID=140 or EventID=141)]]",
            "ScheduledTask", "Scheduled task registered/modified/deleted");
        return _watchers.Count;
    }

    private void Watch(string channel, string xpath, string category, string title)
    {
        EventLogWatcher? watcher = null;
        try
        {
            watcher = new EventLogWatcher(new EventLogQuery(channel, PathType.LogName, xpath));
            watcher.EventRecordWritten += (s, e) =>
            {
                if (e.EventException is not null || e.EventRecord is null) return;
                try
                {
                    using var record = e.EventRecord;
                    var xml = XDocument.Parse(record.ToXml());
                    var attrs = xml.Descendants().Where(x => x.Name.LocalName == "Data" && x.Attribute("Name") is not null)
                        .GroupBy(x => (string)x.Attribute("Name")!)
                        .ToDictionary(g => g.Key, g => g.First().Value[..Math.Min(1000, g.First().Value.Length)],
                            StringComparer.OrdinalIgnoreCase);
                    var evt = new SecurityEvent
                    {
                        Source = channel, Category = category, Title = title, EventId = record.Id,
                        TimestampUtc = record.TimeCreated is DateTime t
                            ? new DateTimeOffset(t.ToUniversalTime()) : DateTimeOffset.UtcNow,
                        Attributes = attrs
                    };
                    ThreatScorer.Apply(evt);
                    _publish(evt);
                }
                catch { }
            };
            watcher.Enabled = true;
            _watchers.Add(watcher);
        }
        catch
        {
            watcher?.Dispose(); // channel not enabled, OS variant, or not authorized
        }
    }

    public void Dispose() { foreach (var w in _watchers) w.Dispose(); _watchers.Clear(); }
}
