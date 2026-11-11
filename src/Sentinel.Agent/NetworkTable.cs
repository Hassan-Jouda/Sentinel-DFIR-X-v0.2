using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Sentinel.Core;

namespace Sentinel.Agent;

internal static class NetworkTable
{
    // Windows IP Helper: MIB_TCPROW_OWNER_PID (24 bytes IPv4) / MIB_UDPROW_OWNER_PID (12 bytes).
    // No packet capture or content interception.
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order,
        int af, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order,
        int af, int tableClass, uint reserved);

    private static readonly Dictionary<int, (string Name, string Path)> ProcessCache = [];

    public static List<NetworkConnection> Collect()
    {
        ProcessCache.Clear();
        var result = new List<NetworkConnection>();
        CollectTcp(result);
        CollectUdp(result);
        return result.Take(5000).ToList();
    }

    private static void CollectTcp(List<NetworkConnection> output)
    {
        int size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, 5, 0);
        if (size <= 0 || size > 4_000_000) return;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, 2, 5, 0) != 0) return;
            int count = Math.Min(Math.Max(0, Marshal.ReadInt32(buffer)), Math.Min(20000, Math.Max(0, (size - 4) / 24)));
            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(buffer, 4 + 24 * i);
                var state = Marshal.ReadInt32(row);
                int pid = Marshal.ReadInt32(row, 20);
                var (name, path) = ProcessInfo(pid);
                var remote = IPv4(row, 12);
                output.Add(new NetworkConnection
                {
                    Pid = pid, Protocol = "TCPv4", LocalAddress = IPv4(row, 4), LocalPort = Port(row, 8),
                    RemoteAddress = remote, RemotePort = Port(row, 16), State = state switch
                    { 2 => "LISTEN", 5 => "ESTABLISHED", 3 => "SYN_SENT", 8 => "CLOSE_WAIT", 11 => "TIME_WAIT", _ => state.ToString() },
                    ProcessName = name, ProcessPath = path,
                    PublicRemote = ThreatScorer.IsPublicDestination(remote)
                });
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static void CollectUdp(List<NetworkConnection> output)
    {
        int size = 0;
        _ = GetExtendedUdpTable(IntPtr.Zero, ref size, true, 2, 1, 0);
        if (size <= 0 || size > 4_000_000) return;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, true, 2, 1, 0) != 0) return;
            int count = Math.Min(Math.Max(0, Marshal.ReadInt32(buffer)), Math.Min(20000, Math.Max(0, (size - 4) / 12)));
            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(buffer, 4 + 12 * i);
                int pid = Marshal.ReadInt32(row, 8);
                var (name, path) = ProcessInfo(pid);
                output.Add(new NetworkConnection
                {
                    Pid = pid, Protocol = "UDPv4", LocalAddress = IPv4(row, 0), LocalPort = Port(row, 4),
                    State = "BOUND", ProcessName = name, ProcessPath = path
                });
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string IPv4(IntPtr row, int offset)
    {
        var b = new byte[4]; Marshal.Copy(IntPtr.Add(row, offset), b, 0, 4);
        return new IPAddress(b).ToString();
    }

    private static int Port(IntPtr row, int offset) =>
        (Marshal.ReadByte(row, offset) << 8) | Marshal.ReadByte(row, offset + 1);

    private static (string Name, string Path) ProcessInfo(int pid)
    {
        if (ProcessCache.TryGetValue(pid, out var value)) return value;
        try
        {
            using var process = Process.GetProcessById(pid);
            value = (process.ProcessName, SafePath(process));
        }
        catch { value = ("[exited/protected]", ""); }
        if (ProcessCache.Count > 10000) ProcessCache.Clear();
        ProcessCache[pid] = value;
        return value;
    }

    internal static string SafePath(Process p)
    {
        try { return p.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }
}
