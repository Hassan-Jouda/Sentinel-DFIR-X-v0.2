using System.Diagnostics;
using System.Globalization;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core;

namespace Sentinel.Agent;

public sealed class AgentWorker : BackgroundService
{
    private readonly ILogger<AgentWorker> _logger;
    public AgentWorker(ILogger<AgentWorker> logger) => _logger = logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var queue = Channel.CreateBounded<SecurityEvent>(new BoundedChannelOptions(10_000)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true, SingleWriter = false
        });
        var correlator = new BehaviorCorrelator();
        int dropped = 0;
        void Publish(SecurityEvent evt)
        {
            IndicatorMatcher.Apply(evt);
            if (!queue.Writer.TryWrite(evt)) Interlocked.Increment(ref dropped);
            if (evt.Category != "Alert")
            {
                var correlated = correlator.Observe(evt);
                if (correlated is not null && !queue.Writer.TryWrite(correlated))
                    Interlocked.Increment(ref dropped);
            }
        }
        var writerTask = Task.Run(async () =>
        {
            await foreach (var evt in queue.Reader.ReadAllAsync())
            {
                try { await EventStore.AppendAsync(evt); }
                catch (Exception ex) { _logger.LogWarning(ex, "Unable to append event"); }
            }
        }, CancellationToken.None);

        using var sysmon = new SysmonListener(Publish);
        using var windowsEvents = new WindowsEventsListener(Publish);
        using var startupWatchers = new StartupWatchers(Publish);
        var sysmonActive = sysmon.Start();
        var windowsChannels = windowsEvents.Start();
        var startupCount = startupWatchers.Start();
        Publish(new SecurityEvent
        {
            Category = "Health", Title = "Sentinel Agent v0.2 started",
            Description = $"Sysmon={sysmonActive}; Windows event channels={windowsChannels}; startup watchers={startupCount}. " +
                "Sysmon network event 3 may be disabled until configured. No automatic blocking enabled."
        });

        var seenProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var analyzedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenConnections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? previousAutoRuns = null;
        var patternDetector = new ConnectionPatternDetector();
        var lastPersistence = DateTimeOffset.MinValue;
        var lastHealth = DateTimeOffset.MinValue;
        var lastSnapshot = DateTimeOffset.MinValue;
        int tick = 0;
        List<PersistenceEntry> autoRuns = [];
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));

        try
        {
            do
            {
                var now = DateTimeOffset.UtcNow;
                tick++;
                var processes = GetProcesses();
                var existingKeys = processes.Select(x => $"{x.Pid}:{x.StartUtc?.UtcTicks ?? 0}")
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var process in processes)
                {
                    var key = $"{process.Pid}:{process.StartUtc?.UtcTicks ?? 0}";
                    if (seenProcesses.Add(key) && tick != 1)
                    {
                        var evt = new SecurityEvent
                        {
                            Source = "ProcessPoller", Category = "Process", Title = "Process first observed (polling)",
                            ProcessId = process.Pid,
                            Attributes = new() { ["Image"] = process.Path, ["Name"] = process.Name }
                        };
                        ThreatScorer.Apply(evt);
                        Publish(evt);
                    }
                }
                seenProcesses.IntersectWith(existingKeys);

                // Analyze executables progressively, without rescanning every process on each tick.
                foreach (var process in processes.Where(p => !string.IsNullOrWhiteSpace(p.Path) &&
                           p.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !analyzedFiles.Contains(p.Path))
                         .Take(8))
                {
                    if (!analyzedFiles.Add(process.Path)) continue;
                    var fact = await Task.Run(() => FileInspector.Inspect(process.Path), stoppingToken);
                    if (fact.Error is not null) continue;
                    var evt = new SecurityEvent
                    {
                        Source = "FileInspector", Category = "FileAnalysis", Title = "Executable metadata analyzed",
                        ProcessId = process.Pid,
                        Attributes = new()
                        {
                            ["Image"] = fact.Path, ["SHA256"] = fact.SHA256,
                            ["FileSize"] = fact.SizeBytes.ToString(),
                            ["Entropy"] = fact.SampleEntropy?.ToString("F3", CultureInfo.InvariantCulture) ?? "",
                            ["EntropySampleBytes"] = fact.EntropySampleBytes.ToString(),
                            ["EmbeddedSigner"] = fact.EmbeddedSigner,
                            ["Unsigned"] = fact.EmbeddedSigner.StartsWith("None detected", StringComparison.OrdinalIgnoreCase) ? "true" : "false"
                        }
                    };
                    ThreatScorer.Apply(evt);
                    Publish(evt);
                }
                if (analyzedFiles.Count > 30_000) analyzedFiles.Clear();

                List<NetworkConnection> connections;
                try { connections = NetworkTable.Collect(); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Cannot enumerate endpoints");
                    connections = [];
                }
                var nextConnectionKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var c in connections)
                {
                    if (c.State != "ESTABLISHED" || c.RemoteAddress == "0.0.0.0") continue;
                    string key = $"{c.Protocol}|{c.Pid}|{c.LocalPort}|{c.RemoteAddress}|{c.RemotePort}";
                    nextConnectionKeys.Add(key);
                    if (!seenConnections.Contains(key) && c.PublicRemote)
                    {
                        var evt = new SecurityEvent
                        {
                            Source = "WindowsIpHelper", Category = "Network", Title = "Outbound endpoint first observed",
                            ProcessId = c.Pid,
                            Attributes = new()
                            {
                                ["Image"] = c.ProcessPath, ["ProcessName"] = c.ProcessName,
                                ["DestinationIp"] = c.RemoteAddress, ["DestinationPort"] = c.RemotePort.ToString(),
                                ["LocalAddress"] = c.LocalAddress, ["LocalPort"] = c.LocalPort.ToString()
                            }
                        };
                        ThreatScorer.Apply(evt);
                        Publish(evt);
                        if (tick > 1)
                        {
                            var repeated = patternDetector.Observe(c, now);
                            if (repeated is not null) Publish(repeated);
                        }
                    }
                }
                seenConnections = nextConnectionKeys;

                if (now - lastPersistence >= TimeSpan.FromMinutes(2) || tick == 1)
                {
                    try
                    {
                        autoRuns = AutoRunScanner.Scan();
                        var current = autoRuns.GroupBy(x => x.Location + "|" + x.Name, StringComparer.OrdinalIgnoreCase)
                            .ToDictionary(g => g.Key, g => g.First().Command, StringComparer.OrdinalIgnoreCase);
                        if (previousAutoRuns is not null)
                        {
                            foreach (var entry in autoRuns)
                            {
                                var key = entry.Location + "|" + entry.Name;
                                if (!previousAutoRuns.TryGetValue(key, out var old) || old != entry.Command)
                                {
                                    var evt = new SecurityEvent
                                    {
                                        Source = "AutoRunScanner", Category = "Persistence", Title = "Autostart added/modified",
                                        Attributes = new() { ["Location"] = entry.Location,
                                            ["EntryName"] = entry.Name, ["Command"] = entry.Command }
                                    };
                                    ThreatScorer.Apply(evt);
                                    Publish(evt);
                                }
                            }
                        }
                        previousAutoRuns = current;
                    }
                    catch (Exception ex) { _logger.LogWarning(ex, "Autostart baseline failed"); }
                    lastPersistence = now;
                }
                if (now - lastSnapshot >= TimeSpan.FromSeconds(10))
                {
                    try
                    {
                        await EventStore.WriteSnapshotAsync(new MachineSnapshot
                        {
                            TimestampUtc = now, ProcessCount = processes.Count, SysmonActive = sysmonActive,
                            DroppedEvents = dropped, Connections = connections.Take(3000).ToList(),
                            AutoRuns = autoRuns.Take(500).ToList()
                        }, stoppingToken);
                    }
                    catch (Exception ex) { _logger.LogWarning(ex, "Snapshot writing failed"); }
                    lastSnapshot = now;
                }
                if (now - lastHealth >= TimeSpan.FromSeconds(30))
                {
                    Publish(new SecurityEvent
                    {
                        Category = "Health", Title = "Agent heartbeat",
                        Description = $"Processes={processes.Count}; endpoints={connections.Count}; " +
                            $"Sysmon={sysmonActive}; autostarts={autoRuns.Count}; dropped={dropped}."
                    });
                    lastHealth = now;
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) { _logger.LogError(ex, "Agent loop stopped unexpectedly"); }
        finally
        {
            queue.Writer.TryComplete();
            await writerTask;
        }
    }

    private static List<ProcessFact> GetProcesses()
    {
        var list = new List<ProcessFact>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    DateTimeOffset? start = null;
                    try { start = process.StartTime.ToUniversalTime(); } catch { }
                    list.Add(new ProcessFact
                    {
                        Pid = process.Id, Name = process.ProcessName,
                        Path = NetworkTable.SafePath(process), StartUtc = start
                    });
                }
                catch { /* protected/ephemeral process */ }
            }
        }
        return list;
    }
}
