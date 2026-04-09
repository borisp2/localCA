using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// macOS trust store operations using the <c>security</c> CLI tool.
///
/// <para><b>Behaviour:</b></para>
/// <list type="bullet">
///   <item>Imports certificates into the System keychain (<c>/Library/Keychains/System.keychain</c>)
///         and sets the SSL trust policy to "trustRoot" so the certificate is accepted by
///         browsers and HTTPS clients.</item>
///   <item>Requires <c>sudo</c> / admin privileges for System keychain operations.</item>
///   <item>Falls back to the user's login keychain when System keychain access fails.</item>
/// </list>
///
/// <para><b>Permissions:</b> System keychain write access requires root or an admin user.
/// The class does not escalate privileges; callers must run as root or use sudo.</para>
/// </summary>
public sealed class MacTrustStore : ITrustStore
{
    private readonly IProcessRunner _processRunner;

    private const string SystemKeychain = "/Library/Keychains/System.keychain";

    public MacTrustStore()
        : this(new SystemProcessRunner())
    {
    }

    public MacTrustStore(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public bool ImportCaCertificate(X509Certificate2 certificate)
    {
        string? tempFile = null;
        try
        {
            tempFile = WriteTempPem(certificate);

            // Import into System keychain
            var (importExit, _) = _processRunner.Run("security",
                $"add-trusted-cert -d -r trustRoot -k {SystemKeychain} \"{tempFile}\"");

            if (importExit == 0)
                return true;

            // Fallback: try login keychain (no sudo required)
            var (loginExit, _) = _processRunner.Run("security",
                $"add-trusted-cert -r trustRoot \"{tempFile}\"");

            return loginExit == 0;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            CleanupTempFile(tempFile);
        }
    }

    public bool RemoveCaCertificate(string thumbprint)
    {
        try
        {
            // Find certificates matching the thumbprint hash
            // 'security find-certificate' uses SHA-1 hash (-Z flag outputs the hash)
            var (findExit, findOutput) = _processRunner.Run("security",
                $"find-certificate -a -Z {SystemKeychain}");

            if (findExit != 0)
                return false;

            // Parse output to find the certificate with matching hash
            // Output format: "SHA-1 hash: AABBCC..." followed by certificate attributes
            var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();

            if (!findOutput.Contains(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
                return false;

            // Remove using the delete-certificate command with hash match
            var (deleteExit, _) = _processRunner.Run("security",
                $"delete-certificate -Z {normalizedThumbprint} {SystemKeychain}");

            return deleteExit == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public bool IsCertificateTrusted(string thumbprint)
    {
        try
        {
            var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();

            // Search System keychain
            var (exitCode, output) = _processRunner.Run("security",
                $"find-certificate -a -Z {SystemKeychain}");

            if (exitCode == 0 && output.Contains(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
                return true;

            // Search default (login) keychain
            var (loginExit, loginOutput) = _processRunner.Run("security",
                "find-certificate -a -Z");

            return loginExit == 0 && loginOutput.Contains(normalizedThumbprint, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public int RemoveBySubject(string subjectMatch)
    {
        int removed = 0;

        try
        {
            // Find certificates matching the subject
            var (exitCode, output) = _processRunner.Run("security",
                $"find-certificate -a -c \"{subjectMatch}\" -Z {SystemKeychain}");

            if (exitCode != 0 || string.IsNullOrWhiteSpace(output))
                return 0;

            // Parse SHA-1 hashes from the output and delete each one
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("SHA-1 hash:", StringComparison.OrdinalIgnoreCase))
                    continue;

                var hash = trimmed.Substring("SHA-1 hash:".Length).Trim();
                if (string.IsNullOrEmpty(hash))
                    continue;

                var (deleteExit, _) = _processRunner.Run("security",
                    $"delete-certificate -Z {hash} {SystemKeychain}");

                if (deleteExit == 0)
                    removed++;
            }
        }
        catch (Exception)
        {
            // Keychain access failure
        }

        return removed;
    }

    private static string WriteTempPem(X509Certificate2 certificate)
    {
        var pem = certificate.ExportCertificatePem();
        var tempPath = Path.Combine(Path.GetTempPath(), $"localca-{Guid.NewGuid():N}.pem");
        File.WriteAllText(tempPath, pem);
        return tempPath;
    }

    private static void CleanupTempFile(string? path)
    {
        if (path != null && File.Exists(path))
        {
            try { File.Delete(path); }
            catch { /* best effort */ }
        }
    }
}
