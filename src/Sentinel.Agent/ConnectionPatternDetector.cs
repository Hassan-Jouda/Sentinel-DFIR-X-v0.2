using Sentinel.Core;

namespace Sentinel.Agent;

internal sealed class ConnectionPatternDetector
{
    private readonly Dictionary<string, List<DateTimeOffset>> _connections = [];
    private readonly Dictionary<string, DateTimeOffset> _alerted = [];

    public SecurityEvent? Observe(NetworkConnection connection, DateTimeOffset now)
    {
        if (!connection.PublicRemote || connection.State != "ESTABLISHED") return null;
        var key = $"{connection.Pid}|{connection.RemoteAddress}|{connection.RemotePort}";
        if (!_connections.TryGetValue(key, out var times)) _connections[key] = times = [];
        times.Add(now);
        times.RemoveAll(t => now - t > TimeSpan.FromMinutes(10));
        if (times.Count < 4 || (_alerted.TryGetValue(key, out var last) && now - last < TimeSpan.FromMinutes(15)))
            return null;
        // Repeated observed connections alone do not establish beaconing or C2.
        _alerted[key] = now;
        var evt = new SecurityEvent
        {
            Category = "Network", Source = "ConnectionPatternDetector", ProcessId = connection.Pid,
            Title = "Repeated outbound connections to one endpoint",
            RiskScore = 30, Severity = "Medium",
            Description = "Four distinct connection observations within 10 minutes; investigate periodic callbacks (not proof of a backdoor).",
            Signals = ["Repeated outbound contacts to same destination"],
            MitreTechniques = ["T1071"],
            Attributes = new()
            {
                ["Image"] = connection.ProcessPath, ["DestinationIp"] = connection.RemoteAddress,
                ["DestinationPort"] = connection.RemotePort.ToString(),
                ["ConnectionCount"] = times.Count.ToString()
            }
        };
        if (_connections.Count > 5000)
            foreach (var k in _connections.Where(x => x.Value.All(t => now - t > TimeSpan.FromMinutes(10)))
                                          .Select(x => x.Key).ToList()) _connections.Remove(k);
        return evt;
    }
}
