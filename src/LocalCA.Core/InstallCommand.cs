using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Orchestrates the Phase 1 install: directory layout, CA generation,
/// server cert generation, and artifact export.
/// </summary>
public sealed class InstallCommand
{
    public string RootDir { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA");

    public string AppName { get; init; } = "MyApp";
    public int CaValidDays { get; init; } = 3650;
    public int ServerValidDays { get; init; } = 825;
    public bool Force { get; init; }
    public bool Verbose { get; init; }

    public int Execute()
    {
        var logPath = Path.Combine(RootDir, "install-ca.log");

        // Ensure at least the root dir exists before opening the log
        if (!Directory.Exists(RootDir))
            Directory.CreateDirectory(RootDir);

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
        // Phase 0: Pre-flight
        log.Phase(0, "Pre-flight checks");
        if (DirectoryLayout.HasExistingCa(RootDir) && !Force)
        {
            log.Warn($"CA already exists at {RootDir}. Use --force to overwrite.");
            Console.WriteLine($"CA already exists at {RootDir}. Use --force to overwrite.");
            return 0;
        }

        // Phase 2: Directory structure
        log.Phase(2, "Creating directory structure");
        var created = DirectoryLayout.EnsureDirectories(RootDir);
        foreach (var dir in created)
            log.Info($"Created: {dir}");

        // Phase 3: Root CA
        log.Phase(3, "Generating Root CA");
        var (caCert, caKey) = CertificateAuthority.CreateRootCa(AppName, CaValidDays);
        log.Info($"Root CA generated: {caCert.Subject} (valid until {caCert.NotAfter:yyyy-MM-dd})");

        // Phase 4: Server certificate
        log.Phase(4, "Generating server certificate");
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, ServerValidDays);
        log.Info($"Server cert generated: {serverCert.Subject} (valid until {serverCert.NotAfter:yyyy-MM-dd})");

        // Phase 5: Export artifacts
        log.Phase(5, "Exporting certificate artifacts");
        CertificateExporter.WriteArtifacts(RootDir, caCert, caKey, serverCert);
        log.Info("Exported: ca.key, ca.crt, localhost.key, localhost.crt, localhost.pfx, localhost-fullchain.pem");

        // Summary
        log.Phase(9, "Summary");
        var summary = $"""
            LocalCA install complete.
              Root dir:    {RootDir}
              CA cert:     {Path.Combine(RootDir, "certs", "ca.crt")}
              Server cert: {Path.Combine(RootDir, "server", "localhost.crt")}
              PFX bundle:  {Path.Combine(RootDir, "server", "localhost.pfx")}
              Fullchain:   {Path.Combine(RootDir, "server", "localhost-fullchain.pem")}
            """;
        log.Info(summary);
        Console.WriteLine(summary);

        // Cleanup
        caKey.Dispose();
        caCert.Dispose();
        serverCert.Dispose();

        return 0;
    }
}
