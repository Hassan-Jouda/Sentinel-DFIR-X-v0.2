namespace Sentinel.Core;

// Defensive telemetry only. A detection is a hypothesis, not proof of malware.
public sealed class SecurityEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "Agent";
    public string Category { get; set; } = "System";
    public string Severity { get; set; } = "Info";
    public int RiskScore { get; set; }
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public int? EventId { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessGuid { get; set; }
    public List<string> Signals { get; set; } = [];
    public List<string> MitreTechniques { get; set; } = [];
    public Dictionary<string, string> Attributes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class NetworkConnection
{
    public int Pid { get; set; }
    public string Protocol { get; set; } = "TCPv4";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string ProcessPath { get; set; } = "";
    public bool PublicRemote { get; set; }
}

public sealed class ProcessFact
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTimeOffset? StartUtc { get; set; }
}

public sealed class FileFact
{
    public string Path { get; set; } = "";
    public long SizeBytes { get; set; }
    public string SHA256 { get; set; } = "";
    public double? SampleEntropy { get; set; }
    public long EntropySampleBytes { get; set; }
    public string EmbeddedSigner { get; set; } = "Unknown";
    public bool PortableExecutable { get; set; }
    public string? Error { get; set; }
}

public sealed class PersistenceEntry
{
    public string Location { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
}

public sealed class MachineSnapshot
{
    public DateTimeOffset TimestampUtc { get; set; } = DateTimeOffset.UtcNow;
    public int ProcessCount { get; set; }
    public bool SysmonActive { get; set; }
    public int DroppedEvents { get; set; }
    public List<NetworkConnection> Connections { get; set; } = [];
    public List<PersistenceEntry> AutoRuns { get; set; } = [];
}
