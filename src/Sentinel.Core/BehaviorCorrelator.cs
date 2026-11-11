namespace Sentinel.Core;

public sealed class BehaviorCorrelator
{
    private readonly object _gate = new();
    private sealed class CaseState
    {
        public DateTimeOffset Last = DateTimeOffset.UtcNow;
        public DateTimeOffset LastAlert = DateTimeOffset.MinValue;
        public HashSet<string> Signals = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Categories = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Techniques = new(StringComparer.OrdinalIgnoreCase);
        public int PeakRisk;
    }
    private readonly Dictionary<string, CaseState> _cases = [];
    private readonly Dictionary<int, string> _guidsByPid = [];

    // A weak indicator by itself never triggers the cross-source alert.
    public SecurityEvent? Observe(SecurityEvent evt)
    {
        if (!evt.ProcessId.HasValue || evt.ProcessId.Value <= 4 || evt.Signals.Count == 0) return null;
        var key = $"pid:{evt.ProcessId}";
        lock (_gate)
        {
            if (!string.IsNullOrWhiteSpace(evt.ProcessGuid))
            {
                if (_guidsByPid.TryGetValue(evt.ProcessId.Value, out var prevGuid) &&
                    prevGuid != evt.ProcessGuid) _cases.Remove(key);
                _guidsByPid[evt.ProcessId.Value] = evt.ProcessGuid;
            }
            if (evt.EventId == 1) _cases.Remove(key);
            if (_guidsByPid.Count > 10000) _guidsByPid.Clear();
            if (_cases.Count > 4000)
                foreach (var k in _cases.Where(x => evt.TimestampUtc - x.Value.Last > TimeSpan.FromMinutes(20))
                                        .Select(x => x.Key).ToList()) _cases.Remove(k);
            if (!_cases.TryGetValue(key, out var state)) _cases[key] = state = new CaseState();
            if (evt.TimestampUtc - state.Last > TimeSpan.FromMinutes(20))
                _cases[key] = state = new CaseState();
            state.Last = evt.TimestampUtc;
            state.Categories.Add(evt.Category);
            state.PeakRisk = Math.Max(state.PeakRisk, evt.RiskScore);
            foreach (var sig in evt.Signals) state.Signals.Add(sig);
            foreach (var technique in evt.MitreTechniques) state.Techniques.Add(technique);
            bool independent = state.Categories.Count >= 2;
            bool suspicious = state.Signals.Count >= 3 || state.PeakRisk >= 70;
            if (!independent || !suspicious ||
                evt.TimestampUtc - state.LastAlert < TimeSpan.FromMinutes(10)) return null;
            state.LastAlert = evt.TimestampUtc;
            var signals = state.Signals.Take(12).ToList();
            var score = Math.Clamp(Math.Max(60, state.PeakRisk + 10 * (state.Categories.Count - 1)), 0, 95);
            return new SecurityEvent
            {
                Source = "CorrelationEngine", Category = "Alert", ProcessId = evt.ProcessId,
                ProcessGuid = evt.ProcessGuid, RiskScore = score,
                Severity = score >= 85 ? "Critical" : "High",
                Title = "Correlated suspicious activity — investigation recommended",
                Description = "Multiple evidence categories relate to the same process. This is NOT a confirmed backdoor or reverse shell.",
                Signals = signals, MitreTechniques = state.Techniques.ToList(),
                Attributes = new() { ["CorrelationKey"] = key, ["EvidenceCategories"] = string.Join(",", state.Categories) }
            };
        }
    }
}
