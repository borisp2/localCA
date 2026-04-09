using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// macOS trust store operations using the <c>security</c> CLI tool.
/// <para>
/// Adds/removes CA certificates from the macOS System Keychain
/// (<c>/Library/Keychains/System.keychain</c>) with SSL trust settings
/// via <c>security add-trusted-cert</c> / <c>security remove-trusted-cert</c>.
/// </para>
/// <para>
/// <b>Trust level:</b> <c>add-trusted-cert -d</c> calls both
/// <c>SecKeychainItemImport</c> and <c>SecTrustSettingsSetTrustSettings</c>
/// under the hood, setting the certificate as trusted for SSL. This is
/// equivalent to importing into the Windows Trusted Root CA store.
/// </para>
/// <para>
/// <b>Permissions:</b> Modifying the System Keychain (<c>-d</c> domain)
/// requires root privileges (<c>sudo</c>). Without elevation, only the
/// user login keychain can be modified. The implementation attempts the
/// System Keychain first, then falls back to the user login keychain.
/// </para>
/// </summary>
public sealed class MacOsTrustStore : ITrustStore
{
    private readonly IProcessRunner _processRunner;

    public MacOsTrustStore()
        : this(new SystemProcessRunner())
    {
    }

    public MacOsTrustStore(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public bool ImportCaCertificate(X509Certificate2 certificate)
    {
        // Export to a temp PEM file for the security CLI
        var tempPem = ExportCertToPemFile(certificate);
        try
        {
            // Try System Keychain first (requires sudo / root)
            bool systemOk = RunSecurity(
                "add-trusted-cert",
                "-d", "admin",         // admin trust domain (System Keychain)
                "-r", "trustRoot",     // mark as trusted root
                "-p", "ssl",           // trust for SSL policy
                "-k", "/Library/Keychains/System.keychain",
                tempPem);

            if (systemOk)
                return true;

            // Fall back to user login keychain (no elevation needed)
            return RunSecurity(
                "add-trusted-cert",
                "-r", "trustRoot",
                "-p", "ssl",
                tempPem);
        }
        finally
        {
            TryDeleteFile(tempPem);
        }
    }

    public bool RemoveCaCertificate(string thumbprint)
    {
        // macOS security CLI doesn't support removal by thumbprint directly.
        // We need to find the cert first, export it, then remove it.
        var tempPem = FindAndExportByHash(thumbprint);
        if (tempPem == null)
            return false;

        try
        {
            // Try System Keychain
            bool systemOk = RunSecurity(
                "remove-trusted-cert",
                "-d", "admin",
                tempPem);

            // Also try user keychain (the cert may be in either or both)
            bool userOk = RunSecurity(
                "remove-trusted-cert",
                tempPem);

            return systemOk || userOk;
        }
        finally
        {
            TryDeleteFile(tempPem);
        }
    }

    public bool IsCertificateTrusted(string thumbprint)
    {
        // Use 'security find-certificate' to search by SHA-1 hash.
        // The thumbprint from .NET is the SHA-1 hash in uppercase hex.
        var (exitCode, _) = RunSecurityCapture(
            "find-certificate",
            "-a", "-Z",             // show SHA-1 hash
            "-c", "",               // match any common name
            "/Library/Keychains/System.keychain");

        if (exitCode == 0)
        {
            // Parse output looking for the thumbprint
            if (SearchKeychainForThumbprint(thumbprint, "/Library/Keychains/System.keychain"))
                return true;
        }

        // Also check user login keychain
        return SearchKeychainForThumbprint(thumbprint, null);
    }

    public int RemoveBySubject(string subjectMatch)
    {
        int totalRemoved = 0;

        // Search and remove from System Keychain
        totalRemoved += RemoveBySubjectFromKeychain(subjectMatch, "/Library/Keychains/System.keychain", "admin");

        // Search and remove from user login keychain
        totalRemoved += RemoveBySubjectFromKeychain(subjectMatch, null, null);

        return totalRemoved;
    }

    // ── Helpers ────────────────────────────────────────────────────

    private bool SearchKeychainForThumbprint(string thumbprint, string? keychainPath)
    {
        var args = new List<string> { "find-certificate", "-a", "-Z" };
        if (keychainPath != null)
            args.Add(keychainPath);

        var (exitCode, output) = RunSecurityCapture(args.ToArray());

        if (exitCode != 0)
            return false;

        // The output contains lines like:
        // SHA-1 hash: AB CD EF 12 34 ...
        // We need to compare against the thumbprint (uppercase hex, no spaces)
        var normalizedThumbprint = thumbprint.ToUpperInvariant().Replace(" ", "");

        foreach (var line in output.Split('\n'))
        {
            if (line.TrimStart().StartsWith("SHA-1 hash:", StringComparison.OrdinalIgnoreCase))
            {
                var hashValue = line.Substring(line.IndexOf(':') + 1)
                    .Trim()
                    .Replace(" ", "")
                    .ToUpperInvariant();

                if (hashValue == normalizedThumbprint)
                    return true;
            }
        }

        return false;
    }

    private int RemoveBySubjectFromKeychain(string subjectMatch, string? keychainPath, string? domain)
    {
        int removed = 0;

        // Find certificates matching the subject
        var args = new List<string> { "find-certificate", "-a", "-Z", "-c", subjectMatch };
        if (keychainPath != null)
            args.Add(keychainPath);

        var (exitCode, output) = RunSecurityCapture(args.ToArray());

        if (exitCode != 0)
            return 0;

        // Parse out the matching certificate hashes, then export and remove each
        var hashes = ParseSha1Hashes(output);

        foreach (var hash in hashes)
        {
            // Export the cert to a temp file so we can pass it to remove-trusted-cert
            var tempPem = FindAndExportByHash(hash);
            if (tempPem == null)
                continue;

            try
            {
                var removeArgs = new List<string> { "remove-trusted-cert" };
                if (domain != null)
                {
                    removeArgs.Add("-d");
                    removeArgs.Add(domain);
                }
                removeArgs.Add(tempPem);

                if (RunSecurity(removeArgs.ToArray()))
                    removed++;
            }
            finally
            {
                TryDeleteFile(tempPem);
            }
        }

        return removed;
    }

    private string? FindAndExportByHash(string thumbprint)
    {
        var normalizedThumbprint = thumbprint.ToUpperInvariant().Replace(" ", "");

        // Try System Keychain first, then user keychain
        string?[] keychains = { "/Library/Keychains/System.keychain", null };

        foreach (var keychain in keychains)
        {
            var args = new List<string> { "find-certificate", "-a", "-Z", "-p" };
            if (keychain != null)
                args.Add(keychain);

            var (exitCode, output) = RunSecurityCapture(args.ToArray());
            if (exitCode != 0)
                continue;

            // The output with -p contains interleaved hash lines and PEM blocks.
            // Parse to find the PEM block for our thumbprint.
            var pem = ExtractPemForThumbprint(output, normalizedThumbprint);
            if (pem != null)
            {
                var tempFile = Path.Combine(Path.GetTempPath(), $"localca-{Guid.NewGuid():N}.pem");
                File.WriteAllText(tempFile, pem);
                return tempFile;
            }
        }

        return null;
    }

    internal static string? ExtractPemForThumbprint(string output, string thumbprint)
    {
        // Output format from 'security find-certificate -a -Z -p':
        //     SHA-1 hash: AB CD EF ...
        //     <other attributes>
        //     -----BEGIN CERTIFICATE-----
        //     ...
        //     -----END CERTIFICATE-----
        //     SHA-1 hash: 12 34 56 ...
        //     ...
        string? currentHash = null;
        var pemBuilder = new System.Text.StringBuilder();
        bool inPem = false;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.TrimStart();

            if (trimmed.StartsWith("SHA-1 hash:", StringComparison.OrdinalIgnoreCase))
            {
                // If we were building a PEM and it matches, we would have returned already
                currentHash = trimmed.Substring(trimmed.IndexOf(':') + 1)
                    .Trim()
                    .Replace(" ", "")
                    .ToUpperInvariant();
                pemBuilder.Clear();
                inPem = false;
            }
            else if (trimmed.StartsWith("-----BEGIN CERTIFICATE-----"))
            {
                inPem = true;
                pemBuilder.Clear();
                pemBuilder.AppendLine(trimmed);
            }
            else if (inPem)
            {
                pemBuilder.AppendLine(trimmed);
                if (trimmed.StartsWith("-----END CERTIFICATE-----"))
                {
                    inPem = false;
                    if (currentHash == thumbprint)
                        return pemBuilder.ToString();
                }
            }
        }

        return null;
    }

    private static List<string> ParseSha1Hashes(string output)
    {
        var hashes = new List<string>();
        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("SHA-1 hash:", StringComparison.OrdinalIgnoreCase))
            {
                var hash = trimmed.Substring(trimmed.IndexOf(':') + 1)
                    .Trim()
                    .Replace(" ", "")
                    .ToUpperInvariant();
                if (hash.Length > 0)
                    hashes.Add(hash);
            }
        }
        return hashes;
    }

    private static string ExportCertToPemFile(X509Certificate2 certificate)
    {
        var pem = certificate.ExportCertificatePem();
        var tempFile = Path.Combine(Path.GetTempPath(), $"localca-{Guid.NewGuid():N}.pem");
        File.WriteAllText(tempFile, pem);
        return tempFile;
    }

    private bool RunSecurity(params string[] args)
    {
        var (exitCode, _) = RunSecurityCapture(args);
        return exitCode == 0;
    }

    private (int ExitCode, string Output) RunSecurityCapture(params string[] args)
    {
        var arguments = string.Join(" ", args.Select(QuoteArgument));
        var result = _processRunner.Run("security", arguments);
        return (result.ExitCode, result.Output);
    }

    private static string QuoteArgument(string arg)
    {
        // Quote arguments that contain spaces or special characters
        if (arg.Contains(' ') || arg.Contains('"'))
            return $"\"{arg.Replace("\"", "\\\"")}\"";
        return arg;
    }

    private static void TryDeleteFile(string path)
    {
        try { File.Delete(path); }
        catch { /* best-effort cleanup */ }
    }
}
