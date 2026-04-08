using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Orchestrates the uninstall: removes trust store entries,
/// firewall rules, and optionally deletes all CA files.
/// </summary>
public sealed class UninstallCommand
{
    public string RootDir { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA");

    public string AppName { get; init; } = "MyApp";
    public int HttpsPort { get; init; } = 443;
    public bool RemoveFiles { get; init; }
    public bool YesConfirm { get; init; }
    public bool Verbose { get; init; }

    /// <summary>
    /// Optional trust store for removing CA certificates.
    /// When null on Windows, a default WindowsTrustStore is used.
    /// </summary>
    public ITrustStore? TrustStore { get; init; }

    /// <summary>
    /// Optional firewall manager for removing firewall rules.
    /// When null on Windows, a default WindowsFirewallManager is used.
    /// </summary>
    public IFirewallManager? FirewallManager { get; init; }

    public int Execute()
    {
        var logPath = Path.Combine(
            Path.GetTempPath(), "uninstall-localca.log");

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
        log.Phase(0, "Pre-flight");
        log.Info($"RootDir: {RootDir}");
        log.Info($"AppName: {AppName}");
        log.Info($"Port: {HttpsPort}");
        log.Info($"RemoveFiles: {RemoveFiles}");

        // Confirmation check
        if (!YesConfirm)
        {
            Console.Write($"""

              This will:
                - Remove the Root CA from trust stores
                - Remove firewall rule: '{AppName} HTTPS (localhost:{HttpsPort})'
            """);

            if (RemoveFiles)
                Console.Write($"\n    - DELETE all files in {RootDir}");

            Console.Write("\n\n  Type YES to continue: ");
            var answer = Console.ReadLine();
            if (!string.Equals(answer?.Trim(), "YES", StringComparison.Ordinal))
            {
                log.Warn("User cancelled.");
                Console.WriteLine("  Cancelled.");
                return 0;
            }
            log.Info("User confirmed.");
        }

        // Phase 1: Trust store removal
        log.Phase(1, "Trust Store Cleanup");
        RemoveTrustEntries(log);

        // Phase 2: Firewall rule removal
        log.Phase(2, "Firewall Cleanup");
        RemoveFirewallRule(log);

        // Phase 3: File removal
        log.Phase(3, "File Cleanup");
        if (RemoveFiles)
        {
            RemoveAllFiles(log);
        }
        else
        {
            log.Info($"File removal skipped (use --remove-files to delete {RootDir}).");
        }

        // Summary
        log.Phase(9, "Summary");
        Console.WriteLine("Uninstall complete.");
        log.Info("Uninstall complete.");

        return 0;
    }

    private void RemoveTrustEntries(InstallLogger log)
    {
        var trustStore = TrustStore;
        if (trustStore == null && OperatingSystem.IsWindows())
            trustStore = new WindowsTrustStore();

        if (trustStore == null)
        {
            log.Info("Trust store operations not supported on this platform — skipping.");
            return;
        }

        // Try to get thumbprint from existing CA cert
        var caCertPath = Path.Combine(RootDir, "certs", "ca.crt");
        string? thumbprint = null;

        if (File.Exists(caCertPath))
        {
            try
            {
                using var cert = new X509Certificate2(caCertPath);
                thumbprint = cert.Thumbprint;
                log.Info($"CA cert thumbprint: {thumbprint}");
            }
            catch (Exception ex)
            {
                log.Warn($"Could not read CA cert: {ex.Message}");
            }
        }
        else
        {
            log.Warn($"CA cert not found at {caCertPath} — will search by subject.");
        }

        // Remove by thumbprint
        if (thumbprint != null)
        {
            var removed = trustStore.RemoveCaCertificate(thumbprint);
            if (removed)
                log.Info($"Removed CA certificate by thumbprint: {thumbprint}");
            else
                log.Info("No certificate found with that thumbprint.");
        }

        // Also try subject-based removal as fallback
        var subjectMatch = $"{AppName} Localhost Root CA";
        var subjectRemoved = trustStore.RemoveBySubject(subjectMatch);
        if (subjectRemoved > 0)
            log.Info($"Removed {subjectRemoved} certificate(s) matching subject '{subjectMatch}'.");
    }

    private void RemoveFirewallRule(InstallLogger log)
    {
        var firewallManager = FirewallManager;
        if (firewallManager == null && OperatingSystem.IsWindows())
            firewallManager = new WindowsFirewallManager();

        if (firewallManager == null)
        {
            log.Info("Firewall operations not supported on this platform — skipping.");
            return;
        }

        var ruleName = $"{AppName} HTTPS (localhost:{HttpsPort})";

        if (firewallManager.RuleExists(ruleName))
        {
            var removed = firewallManager.RemoveInboundRule(ruleName);
            if (removed)
                log.Info($"Removed firewall rule: {ruleName}");
            else
                log.Warn($"Failed to remove firewall rule: {ruleName}");
        }
        else
        {
            log.Info($"No firewall rule found: {ruleName}");
        }
    }

    private void RemoveAllFiles(InstallLogger log)
    {
        if (!Directory.Exists(RootDir))
        {
            log.Info($"Directory not found: {RootDir} — nothing to delete.");
            return;
        }

        var files = Directory.GetFiles(RootDir, "*", SearchOption.AllDirectories);
        log.Info($"Deleting {files.Length} files in {RootDir}...");

        // Log key files being deleted
        var keyFiles = new[]
        {
            Path.Combine("private", "ca.key"),
            Path.Combine("certs", "ca.crt"),
            Path.Combine("server", "localhost.key"),
            Path.Combine("server", "localhost.crt"),
            Path.Combine("server", "localhost.pfx"),
            Path.Combine("server", "localhost-fullchain.pem")
        };

        foreach (var relative in keyFiles)
        {
            var full = Path.Combine(RootDir, relative);
            if (File.Exists(full))
                log.Warn($"Deleting: {full}");
        }

        Directory.Delete(RootDir, recursive: true);
        log.Info($"Deleted {RootDir} and all contents.");
    }
}
