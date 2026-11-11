using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using Sentinel.Core;

namespace Sentinel.Desktop;

public partial class MainWindow : Window
{
    private List<SecurityEvent> _events = [];
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(5) };

    public MainWindow()
    {
        InitializeComponent();
        _timer.Tick += (_, _) => { RefreshEvents(); RefreshSnapshot(); };
        _timer.Start();
        RefreshEvents();
        RefreshSnapshot();
        RefreshProcesses();
    }

    private void RefreshEvents()
    {
        try
        {
            _events = EventStore.ReadLatest(1500);
            ApplyFilter();
            TotalText.Text = _events.Count.ToString();
            HighText.Text = _events.Count(x => x.Severity is "High" or "Critical").ToString();
            NetworkText.Text = _events.Count(x => x.Category == "Network").ToString();
            var lastHeartbeat = _events.FirstOrDefault(x => x.Title == "Agent heartbeat");
            StatusText.Text = lastHeartbeat is not null &&
                DateTimeOffset.UtcNow - lastHeartbeat.TimestampUtc < TimeSpan.FromSeconds(65)
                ? "RUNNING" : "NO RECENT HEARTBEAT";
            FooterText.Text = $"Showing latest {_events.Count} events (active file, max 4 MB read). Local evidence: {EventStore.EventsPath}";
        }
        catch (Exception ex)
        {
            FooterText.Text = $"Cannot read local events: {ex.Message}";
            StatusText.Text = "UNKNOWN";
        }
    }

    private void ApplyFilter()
    {
        if (EventsGrid is null) return;
        var index = FilterCombo?.SelectedIndex ?? 0;
        EventsGrid.ItemsSource = index switch
        {
            1 => _events.Where(x => x.Category == "Alert").ToList(),
            2 => _events.Where(x => x.Severity is "High" or "Critical").ToList(),
            3 => _events.Where(x => x.Category == "Network").ToList(),
            4 => _events.Where(x => x.Category is "Process" or "File" or "FileAnalysis").ToList(),
            _ => _events
        };
    }

    private void FilterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        => ApplyFilter();

    private void RefreshSnapshot()
    {
        var snapshot = EventStore.ReadSnapshot();
        if (snapshot is null) return;
        ConnectionsGrid.ItemsSource = snapshot.Connections
            .OrderByDescending(c => c.PublicRemote).ThenBy(c => c.ProcessName).ToList();
        AutoRunsGrid.ItemsSource = snapshot.AutoRuns.OrderBy(a => a.Name).ToList();
        NetworkText.Text = snapshot.Connections.Count.ToString();
        if (snapshot.DroppedEvents > 0)
            FooterText.Text += $" | WARNING: dropped events = {snapshot.DroppedEvents}";
    }

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Title = "Select local file for metadata inspection" };
        if (picker.ShowDialog() == true) FilePathBox.Text = picker.FileName;
    }

    private async void InspectFile_Click(object sender, RoutedEventArgs e)
    {
        var path = FilePathBox.Text.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        { MessageBox.Show("Select an existing local file."); return; }
        InspectButton.IsEnabled = false;
        try
        {
            var result = await Task.Run(() => FileInspector.Inspect(path));
            FileAnalysisBox.Text = JsonSerializer.Serialize(result,
                new JsonSerializerOptions { WriteIndented = true }) +
                "\n\nNOTE: High entropy can be legitimate compression/encryption. " +
                "Embedded signer presence does NOT imply a trusted/valid signature. " +
                "An empty hash means the file exceeded the 100 MiB hashing cap.";
        }
        catch (Exception ex) { FileAnalysisBox.Text = "Inspection failed: " + ex.Message; }
        finally { InspectButton.IsEnabled = true; }
    }

    private void RefreshProcesses()
    {
        var list = new List<ProcessRow>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    list.Add(new ProcessRow
                    {
                        Name = process.ProcessName,
                        Id = process.Id,
                        MemoryMb = (process.WorkingSet64 / 1024.0 / 1024.0).ToString("F1"),
                        StartTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks
                    });
                }
                catch { /* No access to protected process. */ }
            }
        }
        ProcessesGrid.ItemsSource = list.OrderBy(x => x.Name).ToList();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        RefreshEvents(); RefreshSnapshot(); RefreshProcesses();
    }
    private void RefreshProcesses_Click(object sender, RoutedEventArgs e) => RefreshProcesses();

    private void EventsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EventsGrid.SelectedItem is SecurityEvent evt)
            DetailsBox.Text = JsonSerializer.Serialize(evt,
                new JsonSerializerOptions { WriteIndented = true });
    }

    private void EndProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessesGrid.SelectedItem is not ProcessRow row) return;
        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "System", "Idle", "lsass", "wininit", "csrss", "services", "smss", "winlogon" };
        if (row.Id <= 4 || row.Id == Environment.ProcessId || blocked.Contains(row.Name))
        {
            MessageBox.Show("This process is protected by the prototype's safety policy.");
            return;
        }
        var answer = MessageBox.Show(
            $"End process {row.Name} (PID {row.Id})?\nThis may cause data loss. This is a manual action.",
            "Confirm process termination", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            using var p = Process.GetProcessById(row.Id);
            if (!p.ProcessName.Equals(row.Name, StringComparison.OrdinalIgnoreCase) ||
                p.StartTime.ToUniversalTime().Ticks != row.StartTimeUtcTicks)
                throw new InvalidOperationException("PID was reused or process changed. Refresh the process list.");
            p.Kill();
            MessageBox.Show("Termination requested. Check whether process has exited.");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Unable to terminate process"); }
        RefreshProcesses();
    }

    private void ExportReport_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "HTML report|*.html", FileName = "Sentinel-Report.html",
            Title = "Export local security event report"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            var html = new StringBuilder();
            html.Append("<!doctype html><html><head><meta charset='utf-8'><title>Sentinel Report</title>");
            html.Append("<style>body{font-family:Segoe UI,Arial;margin:30px;color:#192337}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left}tr:nth-child(even){background:#f1f5f9}</style>");
            html.Append("</head><body><h1>Sentinel DFIR Event Report</h1>");
            html.Append("<p>Generated UTC: ").Append(DateTimeOffset.UtcNow.ToString("u")).Append("</p>");
            html.Append("<p>Research preview: heuristic scores are not proof of malware. Only recent events in the current log are exported; rotated logs remain on disk.</p>");
            html.Append("<table><tr><th>UTC</th><th>Level</th><th>Source</th><th>Category</th><th>Title</th><th>Details</th><th>Signals</th><th>ATT&amp;CK</th></tr>");
            foreach (var x in _events)
            {
                html.Append("<tr><td>").Append(WebUtility.HtmlEncode(x.TimestampUtc.ToString("u")))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(x.Severity))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(x.Source))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(x.Category))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(x.Title))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(x.Description))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(string.Join("; ", x.Signals)))
                    .Append("</td><td>").Append(WebUtility.HtmlEncode(string.Join(", ", x.MitreTechniques)))
                    .Append("</td></tr>");
            }
            html.Append("</table></body></html>");
            File.WriteAllText(dialog.FileName, html.ToString(), new UTF8Encoding(false));
            using var stream = File.OpenRead(dialog.FileName);
            var sha = Convert.ToHexString(SHA256.HashData(stream));
            File.WriteAllText(dialog.FileName + ".sha256", $"{sha}  {Path.GetFileName(dialog.FileName)}");
            MessageBox.Show("HTML report and SHA-256 checksum exported. These are snapshots, not a full forensic acquisition.");
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Export failed"); }
    }

    public sealed class ProcessRow
    {
        public string Name { get; set; } = "";
        public int Id { get; set; }
        public string MemoryMb { get; set; } = "";
        public long StartTimeUtcTicks { get; set; }
    }
}
