using System.Text.Json;

namespace Sentinel.Core;

public sealed class IndicatorSet
{
    public List<string> SHA256 { get; set; } = [];
    public List<string> IPs { get; set; } = [];
    public List<string> Domains { get; set; } = [];
}

public static class IndicatorMatcher
{
    private static readonly object Gate = new();
    private static DateTime LastCheck = DateTime.MinValue;
    private static DateTime LastWrite = DateTime.MinValue;
    private static HashSet<string> Hashes = new(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> Ips = new(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> Domains = new(StringComparer.OrdinalIgnoreCase);
    public static string IndicatorsPath => Path.Combine(EventStore.DataDirectory, "indicators.json");

    // Local, user-supplied, exact-match IOCs; no network calls, no untrusted code execution.
    public static void Apply(SecurityEvent evt)
    {
        ReloadIfChanged();
        var a = evt.Attributes;
        string Get(string name) => a.TryGetValue(name, out var v) ? v : "";
        var hits = new List<string>();
        lock (Gate)
        {
            var sha = Get("SHA256");
            var ip = Get("DestinationIp");
            var domain = Get("QueryName").TrimEnd('.');
            if (sha.Length == 64 && Hashes.Contains(sha)) hits.Add("SHA-256 matches user-supplied IOC");
            if (!string.IsNullOrEmpty(ip) && Ips.Contains(ip)) hits.Add("Remote IP matches user-supplied IOC");
            if (!string.IsNullOrEmpty(domain) && Domains.Any(d =>
                domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
                hits.Add("DNS name matches user-supplied IOC");
        }
        if (hits.Count == 0) return;
        evt.RiskScore = Math.Max(evt.RiskScore, 90);
        evt.Severity = "Critical";
        foreach (var hit in hits) evt.Signals.Add(hit);
        evt.Description = string.Join("; ", hits) + ". Validate indicator provenance and event context before responding.";
    }

    private static void ReloadIfChanged()
    {
        lock (Gate)
        {
            var now = DateTime.UtcNow;
            if ((now - LastCheck) < TimeSpan.FromSeconds(10)) return;
            LastCheck = now;
            DateTime mtime;
            try { mtime = File.Exists(IndicatorsPath) ? File.GetLastWriteTimeUtc(IndicatorsPath) : DateTime.MinValue; }
            catch { return; }
            if (mtime == LastWrite) return;
            try
            {
                var indicators = mtime == DateTime.MinValue ? new IndicatorSet() :
                    JsonSerializer.Deserialize<IndicatorSet>(File.ReadAllText(IndicatorsPath)) ?? new IndicatorSet();
                if (indicators.SHA256.Count > 100000 || indicators.IPs.Count > 100000 || indicators.Domains.Count > 100000)
                    throw new InvalidDataException("Excessive indicator count");
                Hashes = indicators.SHA256.Where(s => s.Length == 64 && s.All(Uri.IsHexDigit))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                Ips = indicators.IPs.Where(s => System.Net.IPAddress.TryParse(s, out _))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                Domains = indicators.Domains.Select(s => s.Trim().TrimEnd('.').ToLowerInvariant())
                    .Where(s => s.Length is > 3 and < 255 && !s.Contains('*'))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                LastWrite = mtime;
            }
            catch { /* invalid file: preserve the previous valid indicator set */ }
        }
    }
}
