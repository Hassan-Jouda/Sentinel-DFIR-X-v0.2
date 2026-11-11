using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sentinel.Core;

public static class FileInspector
{
    // Bounded reads. Entropy is calculated on a sample, not the complete file.
    private const int EntropySampleLimit = 1024 * 1024;
    private const long HashLimit = 100L * 1024 * 1024;

    public static FileFact Inspect(string filePath)
    {
        var fact = new FileFact { Path = filePath };
        try
        {
            var info = new FileInfo(filePath);
            fact.SizeBytes = info.Length;
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan))
            {
                var sample = new byte[(int)Math.Min(EntropySampleLimit, info.Length)];
                var read = 0;
                while (read < sample.Length)
                {
                    var n = stream.Read(sample, read, sample.Length - read);
                    if (n == 0) break;
                    read += n;
                }
                fact.PortableExecutable = read >= 2 && sample[0] == (byte)'M' && sample[1] == (byte)'Z';
                fact.EntropySampleBytes = read;
                if (read >= 1024) fact.SampleEntropy = CalculateEntropy(sample.AsSpan(0, read));
                if (info.Length <= HashLimit)
                {
                    stream.Position = 0;
                    fact.SHA256 = Convert.ToHexString(SHA256.HashData(stream));
                }
            }
            if (fact.PortableExecutable)
            {
                try
                {
#pragma warning disable SYSLIB0057 // Presence of embedded signer only; no trust verification.
                    using var signer = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                    fact.EmbeddedSigner = signer.Subject;
                }
                catch (CryptographicException) { fact.EmbeddedSigner = "None detected (NOT trust-verified)"; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { fact.EmbeddedSigner = "Cannot inspect"; }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            fact.Error = ex.Message;
        }
        return fact;
    }

    public static double CalculateEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> buckets = stackalloc int[256];
        foreach (var b in data) buckets[b]++;
        var h = 0.0;
        foreach (int n in buckets)
        {
            if (n == 0) continue;
            double p = (double)n / data.Length;
            h -= p * Math.Log2(p);
        }
        return Math.Round(h, 3);
    }
}
