using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LocalCA.Core;

/// <summary>
/// Information about a single certificate artifact.
/// </summary>
public sealed class CertificateInfo
{
    public bool Exists { get; init; }
    public string FilePath { get; init; } = "";
    public string? Subject { get; init; }
    public string? Issuer { get; init; }
    public string? Thumbprint { get; init; }
    public DateTime? NotBefore { get; init; }
    public DateTime? NotAfter { get; init; }
    public int? KeySizeBits { get; init; }
    public IReadOnlyList<string> DnsNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> IpAddresses { get; init; } = Array.Empty<string>();
    public bool? IsCa { get; init; }
    public bool? IsTrusted { get; init; }
    public string? Error { get; init; }

    public int DaysRemaining => NotAfter.HasValue
        ? Math.Max(0, (int)(NotAfter.Value - DateTime.UtcNow).TotalDays)
        : 0;
}

/// <summary>
/// Overall status report for the LocalCA installation.
/// </summary>
public sealed class StatusReport
{
    public CertificateInfo CaCertificate { get; init; } = new() { Exists = false };
    public CertificateInfo ServerCertificate { get; init; } = new() { Exists = false };
    public bool CaKeyExists { get; init; }
    public bool ServerKeyExists { get; init; }
    public bool PfxExists { get; init; }
    public bool FullchainExists { get; init; }
    public string RootDir { get; init; } = "";

    public string FormatReport()
    {
        var sb = new StringBuilder();

        sb.AppendLine($"LocalCA Status — {RootDir}");
        sb.AppendLine(new string('─', 60));

        // File existence
        sb.AppendLine();
        sb.AppendLine("Artifacts:");
        sb.AppendLine($"  CA certificate:       {(CaCertificate.Exists ? "present" : "MISSING")}");
        sb.AppendLine($"  CA private key:       {(CaKeyExists ? "present" : "MISSING")}");
        sb.AppendLine($"  Server certificate:   {(ServerCertificate.Exists ? "present" : "MISSING")}");
        sb.AppendLine($"  Server private key:   {(ServerKeyExists ? "present" : "MISSING")}");
        sb.AppendLine($"  PFX bundle:           {(PfxExists ? "present" : "MISSING")}");
        sb.AppendLine($"  Fullchain PEM:        {(FullchainExists ? "present" : "MISSING")}");

        // CA details
        if (CaCertificate.Exists && CaCertificate.Error == null)
        {
            sb.AppendLine();
            sb.AppendLine("CA Certificate:");
            sb.AppendLine($"  Subject:     {CaCertificate.Subject}");
            sb.AppendLine($"  Thumbprint:  {CaCertificate.Thumbprint}");
            sb.AppendLine($"  Valid from:  {CaCertificate.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Valid until: {CaCertificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Key size:    {CaCertificate.KeySizeBits} bits");
            sb.AppendLine($"  Days left:   {CaCertificate.DaysRemaining}");
            sb.AppendLine($"  Is CA:       {CaCertificate.IsCa}");
            if (CaCertificate.IsTrusted.HasValue)
                sb.AppendLine($"  Trusted:     {CaCertificate.IsTrusted.Value}");
        }
        else if (CaCertificate.Error != null)
        {
            sb.AppendLine();
            sb.AppendLine($"CA Certificate: ERROR — {CaCertificate.Error}");
        }

        // Server details
        if (ServerCertificate.Exists && ServerCertificate.Error == null)
        {
            sb.AppendLine();
            sb.AppendLine("Server Certificate:");
            sb.AppendLine($"  Subject:     {ServerCertificate.Subject}");
            sb.AppendLine($"  Issuer:      {ServerCertificate.Issuer}");
            sb.AppendLine($"  Thumbprint:  {ServerCertificate.Thumbprint}");
            sb.AppendLine($"  Valid from:  {ServerCertificate.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Valid until: {ServerCertificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  Key size:    {ServerCertificate.KeySizeBits} bits");
            sb.AppendLine($"  Days left:   {ServerCertificate.DaysRemaining}");

            if (ServerCertificate.DnsNames.Count > 0)
                sb.AppendLine($"  DNS SANs:    {string.Join(", ", ServerCertificate.DnsNames)}");
            if (ServerCertificate.IpAddresses.Count > 0)
                sb.AppendLine($"  IP SANs:     {string.Join(", ", ServerCertificate.IpAddresses)}");
        }
        else if (ServerCertificate.Error != null)
        {
            sb.AppendLine();
            sb.AppendLine($"Server Certificate: ERROR — {ServerCertificate.Error}");
        }

        return sb.ToString();
    }
}

/// <summary>
/// Reports on the status of a LocalCA installation, including
/// file existence, certificate metadata, and trust status.
/// </summary>
public static class CertificateStatusReporter
{
    /// <summary>
    /// Build a status report for the LocalCA installation at rootDir.
    /// Optionally checks trust store status via the provided ITrustStore.
    /// </summary>
    public static StatusReport GetStatus(string rootDir, ITrustStore? trustStore = null)
    {
        var caCertPath = Path.Combine(rootDir, "certs", "ca.crt");
        var caKeyPath = Path.Combine(rootDir, "private", "ca.key");
        var serverCertPath = Path.Combine(rootDir, "server", "localhost.crt");
        var serverKeyPath = Path.Combine(rootDir, "server", "localhost.key");
        var pfxPath = Path.Combine(rootDir, "server", "localhost.pfx");
        var fullchainPath = Path.Combine(rootDir, "server", "localhost-fullchain.pem");

        var caInfo = LoadCertificateInfo(caCertPath, trustStore);
        var serverInfo = LoadCertificateInfo(serverCertPath, trustStore: null);

        return new StatusReport
        {
            RootDir = rootDir,
            CaCertificate = caInfo,
            ServerCertificate = serverInfo,
            CaKeyExists = File.Exists(caKeyPath),
            ServerKeyExists = File.Exists(serverKeyPath),
            PfxExists = File.Exists(pfxPath),
            FullchainExists = File.Exists(fullchainPath)
        };
    }

    private static CertificateInfo LoadCertificateInfo(string certPath, ITrustStore? trustStore)
    {
        if (!File.Exists(certPath))
        {
            return new CertificateInfo
            {
                Exists = false,
                FilePath = certPath
            };
        }

        try
        {
            using var cert = new X509Certificate2(certPath);

            var basicConstraints = cert.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .FirstOrDefault();

            var san = cert.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .FirstOrDefault();

            var dnsNames = san?.EnumerateDnsNames().ToList() ?? new List<string>();
            var ips = san?.EnumerateIPAddresses().Select(ip => ip.ToString()).ToList() ?? new List<string>();

            bool? isTrusted = null;
            if (trustStore != null)
                isTrusted = trustStore.IsCertificateTrusted(cert.Thumbprint);

            return new CertificateInfo
            {
                Exists = true,
                FilePath = certPath,
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                NotBefore = cert.NotBefore.ToUniversalTime(),
                NotAfter = cert.NotAfter.ToUniversalTime(),
                KeySizeBits = cert.PublicKey.GetRSAPublicKey()?.KeySize,
                DnsNames = dnsNames,
                IpAddresses = ips,
                IsCa = basicConstraints?.CertificateAuthority,
                IsTrusted = isTrusted
            };
        }
        catch (Exception ex)
        {
            return new CertificateInfo
            {
                Exists = true,
                FilePath = certPath,
                Error = ex.Message
            };
        }
    }
}
