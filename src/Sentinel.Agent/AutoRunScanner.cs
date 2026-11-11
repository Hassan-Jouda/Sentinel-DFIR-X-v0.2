using Microsoft.Win32;
using Sentinel.Core;

namespace Sentinel.Agent;

internal static class AutoRunScanner
{
    private static readonly string[] KeyPaths = [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    ];

    public static List<PersistenceEntry> Scan()
    {
        var result = new List<PersistenceEntry>();
        // HKCU in a LocalSystem service refers to SYSTEM, not the signed-in user.
        // Enumerate loaded user hives under HKEY_USERS instead.
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.Users })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                string[] userPrefixes = hive == RegistryHive.Users
                    ? baseKey.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
                        && !s.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)).ToArray()
                    : new[] { "" };
                foreach (var prefix in userPrefixes)
                foreach (var path in KeyPaths)
                {
                    var full = string.IsNullOrEmpty(prefix) ? path : prefix + @"\" + path;
                    using var sub = baseKey.OpenSubKey(full, false);
                    if (sub is null) continue;
                    foreach (var name in sub.GetValueNames())
                    {
                        if (result.Count >= 500) return result;
                        try
                        {
                            var raw = sub.GetValue(name, "", RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                            result.Add(new PersistenceEntry
                            {
                                Location = $"{hive}\\{full} ({view})", Name = name,
                                Command = raw[..Math.Min(raw.Length, 1000)]
                            });
                        }
                        catch { /* inaccessible registry value */ }
                    }
                }
            }
            catch { /* unavailable hive */ }
        }
        foreach (var folder in StartupFolders())
        {
            if (!Directory.Exists(folder)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(folder).Take(100))
                    result.Add(new PersistenceEntry { Location = folder, Name = Path.GetFileName(file), Command = file });
            }
            catch { /* protected folder */ }
        }
        return result;
    }

    public static List<string> StartupFolders()
    {
        var result = new List<string>();
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrEmpty(common)) result.Add(common);
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var drive = Path.GetPathRoot(system) ?? @"C:\";
        var usersRoot = Path.Combine(drive, "Users");
        if (Directory.Exists(usersRoot))
        {
            try
            {
                foreach (var folder in Directory.EnumerateDirectories(usersRoot).Take(100))
                    result.Add(Path.Combine(folder, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
            }
            catch { }
        }
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
