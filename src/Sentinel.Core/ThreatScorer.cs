using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Sentinel.Core;

public static class ThreatScorer
{
    // Explainable rules: indicators accumulate, but cannot certify a malicious binary.
    public static void Apply(SecurityEvent evt)
    {
        var a = evt.Attributes;
        string Get(string k) => a.TryGetValue(k, out var v) ? v : "";
        var image = Get("Image");
        if (string.IsNullOrWhiteSpace(image)) image = Get("ProcessPath");
        var command = Get("CommandLine");
        var parent = Get("ParentImage");
        var target = Get("TargetObject");
        var targetFile = Get("TargetFilename");
        var dest = Get("DestinationIp");
        var signals = new List<string>();
        var mitre = new List<string>();
        int score = 0;
        void Add(int weight, string reason, string? technique = null)
        {
            score += weight;
            signals.Add(reason);
            if (technique is not null) mitre.Add(technique);
        }

        if (evt.Category is "Process" or "FileAnalysis")
        {
            if (UserWritablePath(image)) Add(20, "Executable launched from a user-writable path", "T1204");
            if (image.EndsWith("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
                (command.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase) ||
                 System.Text.RegularExpressions.Regex.IsMatch(command, @"(?:^|\s)-enc(?:\s|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)))
                Add(40, "Encoded PowerShell command line", "T1059.001");
            if ((parent.EndsWith("winword.exe", StringComparison.OrdinalIgnoreCase) ||
                 parent.EndsWith("excel.exe", StringComparison.OrdinalIgnoreCase) ||
                 parent.EndsWith("outlook.exe", StringComparison.OrdinalIgnoreCase)) &&
                (image.EndsWith("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                 image.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                 image.EndsWith("wscript.exe", StringComparison.OrdinalIgnoreCase)))
                Add(35, "Office application spawned a script/command interpreter", "T1204.002");
            if (command.Contains("System.Net.Sockets.TcpClient", StringComparison.OrdinalIgnoreCase) &&
                command.Contains("GetStream", StringComparison.OrdinalIgnoreCase))
                Add(60, "Command line contains an interactive TCP-client scripting pattern; investigate possible remote control", "T1059.001");
            if ((image.EndsWith("nc.exe", StringComparison.OrdinalIgnoreCase) ||
                 image.EndsWith("ncat.exe", StringComparison.OrdinalIgnoreCase)) &&
                (command.Contains(" -e ", StringComparison.OrdinalIgnoreCase) ||
                 command.Contains(" --exec ", StringComparison.OrdinalIgnoreCase)))
                Add(60, "Netcat command includes process-execution option; investigate authorization", "T1095");
            if ((image.EndsWith("mshta.exe", StringComparison.OrdinalIgnoreCase) ||
                 image.EndsWith("regsvr32.exe", StringComparison.OrdinalIgnoreCase)) &&
                (command.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                 command.Contains("https://", StringComparison.OrdinalIgnoreCase)))
                Add(35, "System utility launched with a remote resource", "T1218");
            if (Get("Unsigned") == "true") Add(13, "No embedded signer certificate detected (trust NOT verified)");
            if (double.TryParse(Get("Entropy"), NumberStyles.Float, CultureInfo.InvariantCulture, out var h) && h >= 7.45 &&
                long.TryParse(Get("EntropySampleBytes"), out var n) && n >= 65536)
                Add(12, $"High sample entropy ({h:F2} bits/byte); compressed or packed files may be benign", "T1027");
        }
        if (evt.Category == "Registry" &&
            (target.Contains(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
             target.Contains(@"\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase)))
            Add(30, "Autostart registry value changed", "T1547.001");
        if (evt.Category == "Persistence")
        {
            Add(30, "New or changed autostart entry", "T1547.001");
            if (UserWritablePath(Get("Command"))) Add(18, "Autostart entry references a user-writable location");
        }
        if (evt.Category == "ScheduledTask" && evt.EventId is 106 or 140)
            Add(25, "Scheduled task creation or update observed", "T1053.005");
        if (evt.EventId is 19 or 20 or 21)
            Add(40, "Sysmon event associated with WMI event subscription", "T1546.003");
        if (evt.Category == "File" &&
            targetFile.Contains(@"\Start Menu\Programs\Startup\", StringComparison.OrdinalIgnoreCase))
            Add(35, "Startup folder changed", "T1547.001");
        if (evt.Category == "Network" && IsPublicDestination(dest))
        {
            Add(10, "Public outbound destination observed", "T1071");
            if (UserWritablePath(image)) Add(23, "User-writable executable communicating externally");
            if (Get("Unsigned") == "true") Add(13, "Outbound process lacks detected embedded certificate");
            if (new[] { "4444", "5555", "6666", "9001", "1337" }.Contains(Get("DestinationPort")))
                Add(8, "Unusual destination port (not proof of remote control)");
        }
        if (evt.EventId == 8) Add(50, "Cross-process remote thread creation observed", "T1055");
        if (evt.EventId == 25) Add(70, "Sysmon reported process tampering behavior", "T1055.012");
        if (evt.EventId == 7045)
        {
            Add(30, "New Windows service installed", "T1543.003");
            if (UserWritablePath(Get("ImagePath")) || UserWritablePath(Get("ServiceFileName")))
                Add(20, "Service executable points to user-writable location");
        }
        if (evt.EventId == 1116) Add(75, "Microsoft Defender reported a malware detection");
        evt.RiskScore = Math.Min(100, Math.Max(evt.RiskScore, score));
        evt.Severity = evt.RiskScore switch { >= 85 => "Critical", >= 60 => "High", >= 25 => "Medium", _ => "Info" };
        foreach (var signal in signals) if (!evt.Signals.Contains(signal)) evt.Signals.Add(signal);
        foreach (var tag in mitre) if (!evt.MitreTechniques.Contains(tag)) evt.MitreTechniques.Add(tag);
        if (evt.Signals.Count > 0 && string.IsNullOrWhiteSpace(evt.Description))
            evt.Description = string.Join("; ", evt.Signals) + ". Corroborate before taking action.";
    }

    public static bool UserWritablePath(string path) =>
        path.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase);

    public static bool IsPublicDestination(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || !IPAddress.TryParse(value, out var ip)) return false;
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) return !ip.IsIPv4MappedToIPv6;
        byte[] b = ip.GetAddressBytes();
        return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 &&
            !(b[0] == 169 && b[1] == 254) &&
            !(b[0] == 172 && b[1] is >= 16 and <= 31) &&
            !(b[0] == 192 && b[1] == 168) &&
            !(b[0] == 100 && b[1] is >= 64 and <= 127) &&
            !(b[0] == 192 && b[1] == 0 && b[2] == 2) &&
            !(b[0] == 198 && b[1] == 51 && b[2] == 100) &&
            !(b[0] == 203 && b[1] == 0 && b[2] == 113);
    }
}
