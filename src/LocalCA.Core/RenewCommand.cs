using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Orchestrates server certificate renewal: validates CA exists,
/// checks expiry threshold, backs up current artifacts, generates
/// a new server cert, verifies it, and optionally restarts a service.
/// </summary>
public sealed class RenewCommand
{
    public string RootDir { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA");

    public string AppName { get; init; } = "MyApp";
    public int ServerValidDays { get; init; } = 825;
    public int RenewThresholdDays { get; init; } = 30;
    public string? RestartServiceName { get; init; }
    public bool Force { get; init; }
    public bool Verbose { get; init; }

    /// <summary>
    /// Optional service controller for restarting services after renewal.
    /// When null and RestartServiceName is set, a default WindowsServiceController is used.
    /// </summary>
    public IServiceController? ServiceController { get; init; }

    public int Execute()
    {
        var logPath = Path.Combine(RootDir, "renew-cert.log");

        if (!Directory.Exists(RootDir))
        {
            Console.Error.WriteLine($"LocalCA directory not found: {RootDir}");
            return 1;
        }

        using var log = new InstallLogger(logPath, Verbose);

        try
        {
            return ExecuteCore(log);
        }
        catch (Exception ex)
        {
            log.Error($"Unexpected error: {ex}");
            Console.Error.WriteLine($"Fatal: {ex.Message}");
            return 99;
        }
    }

    private int ExecuteCore(InstallLogger log)
    {
        log.Phase(0, "Pre-flight — validating CA artifacts");

        var caKeyPath = Path.Combine(RootDir, "private", "ca.key");
        var caCertPath = Path.Combine(RootDir, "certs", "ca.crt");
        var serverDir = Path.Combine(RootDir, "server");
        var serverCertPath = Path.Combine(serverDir, "localhost.crt");

        // Validate required CA artifacts exist
        if (!File.Exists(caKeyPath))
        {
            log.Error($"CA private key not found: {caKeyPath}");
            Console.Error.WriteLine("CA not found. Run 'localca install' first.");
            return 1;
        }

        if (!File.Exists(caCertPath))
        {
            log.Error($"CA certificate not found: {caCertPath}");
            Console.Error.WriteLine("CA not found. Run 'localca install' first.");
            return 1;
        }

        if (!Directory.Exists(serverDir))
        {
            log.Error($"Server directory not found: {serverDir}");
            Console.Error.WriteLine("CA not found. Run 'localca install' first.");
            return 1;
        }

        log.Info("CA structure validated.");

        // Check current cert expiry
        log.Phase(1, "Checking certificate expiry");
        bool needsRenewal;
        int daysRemaining = 0;

        if (!File.Exists(serverCertPath))
        {
            log.Warn("No existing server certificate found — will generate fresh.");
            needsRenewal = true;
        }
        else
        {
            using var currentCert = new X509Certificate2(serverCertPath);
            daysRemaining = Math.Max(0, (int)(currentCert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
            log.Info($"Current cert expires: {currentCert.NotAfter:yyyy-MM-dd} ({daysRemaining} days remaining)");

            if (Force)
            {
                log.Warn("Force flag set — renewing regardless of expiry.");
                needsRenewal = true;
            }
            else if (daysRemaining <= RenewThresholdDays)
            {
                log.Warn($"Within renewal threshold ({RenewThresholdDays} days) — renewal needed.");
                needsRenewal = true;
            }
            else
            {
                log.Info($"Certificate is still valid for {daysRemaining} days — no renewal needed.");
                needsRenewal = false;
            }
        }

        if (!needsRenewal)
        {
            Console.WriteLine($"No renewal needed. Certificate valid for {daysRemaining} days. Use --force to override.");
            return 0;
        }

        // Backup existing server artifacts
        log.Phase(2, "Backing up current server artifacts");
        if (Directory.GetFiles(serverDir).Length > 0)
        {
            var backupDir = BackupManager.BackupServerArtifacts(serverDir);
            log.Info($"Backup created: {backupDir}");
        }
        else
        {
            log.Info("No files to back up.");
        }

        // Generate new server certificate using existing CA
        log.Phase(3, "Generating new server certificate");

        var caCertPem = File.ReadAllText(caCertPath);
        var caKeyPem = File.ReadAllText(caKeyPath);

        using var caKey = RSA.Create();
        caKey.ImportFromPem(caKeyPem);

        using var caCertBase = new X509Certificate2(caCertPath);
        using var caCert = caCertBase.CopyWithPrivateKey(caKey);

        var (serverCert, serverKey) = ServerCertificateGenerator.CreateServerCertificateWithKey(caCert, ServerValidDays);

        log.Info($"New server cert generated: {serverCert.Subject} (valid until {serverCert.NotAfter:yyyy-MM-dd})");

        // Write artifacts — use the pre-captured serverKey which is guaranteed
        // exportable, avoiding Windows CNG handle issues.
        log.Phase(4, "Exporting renewed certificate artifacts");

        File.WriteAllText(
            Path.Combine(serverDir, "localhost.key"),
            CertificateExporter.ExportPrivateKeyPem(serverKey));

        File.WriteAllText(
            Path.Combine(serverDir, "localhost.crt"),
            CertificateExporter.ExportCertificatePem(serverCert));

        File.WriteAllBytes(
            Path.Combine(serverDir, "localhost.pfx"),
            CertificateExporter.ExportPfx(serverCert));

        File.WriteAllText(
            Path.Combine(serverDir, "localhost-fullchain.pem"),
            CertificateExporter.ExportFullchainPem(serverCert, caCertBase, serverKey));

        log.Info("Exported: localhost.key, localhost.crt, localhost.pfx, localhost-fullchain.pem");

        // Verify the renewed cert
        log.Phase(5, "Verifying renewed certificate");
        var verifyResult = CertificateVerifier.Verify(caCertBase, serverCert);

        if (verifyResult.IsValid)
        {
            log.Info("Chain verification passed.");
        }
        else
        {
            foreach (var error in verifyResult.Errors)
                log.Error($"Verify: {error}");
            Console.Error.WriteLine("Warning: renewed certificate verification has issues.");
        }

        serverKey.Dispose();
        serverCert.Dispose();

        // Restart service if configured
        if (!string.IsNullOrWhiteSpace(RestartServiceName))
        {
            log.Phase(6, $"Restarting service: {RestartServiceName}");
            var svc = ServiceController ?? new WindowsServiceController();

            if (svc.ServiceExists(RestartServiceName))
            {
                var restarted = svc.RestartService(RestartServiceName);
                if (restarted)
                    log.Info($"Service '{RestartServiceName}' restarted successfully.");
                else
                    log.Warn($"Service '{RestartServiceName}' restart returned failure.");
            }
            else
            {
                log.Warn($"Service '{RestartServiceName}' not found — skipping restart.");
            }
        }

        // Prune old backups
        log.Phase(7, "Pruning old backups (keeping latest 5)");
        var pruned = BackupManager.PruneBackups(serverDir, keepCount: 5);
        foreach (var dir in pruned)
            log.Info($"Pruned: {Path.GetFileName(dir)}");
        log.Info($"Keeping {BackupManager.ListBackups(serverDir).Count} backup(s).");

        // Summary
        log.Phase(9, "Summary");
        var newExpiry = DateTime.UtcNow.AddDays(ServerValidDays).ToString("yyyy-MM-dd");
        var summary = $"""
            Server certificate renewed.
              Previous: {daysRemaining} days remaining
              New expiry: {newExpiry} ({ServerValidDays} days)
              Root dir: {RootDir}
            """;
        log.Info(summary);
        Console.WriteLine(summary);

        return 0;
    }
}
