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
public sealed class MacOsTrustStore : ITrustStore
{
    private readonly IProcessRunner _processRunner;

    private const string SystemKeychain = "/Library/Keychains/System.keychain";

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
            var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();
            bool removed = false;

            // Try System keychain
            removed |= RemoveFromKeychain(normalizedThumbprint, SystemKeychain);

            // Try login keychain (no explicit keychain path = default/login)
            removed |= RemoveFromKeychain(normalizedThumbprint, keychainPath: null);

            return removed;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private bool RemoveFromKeychain(string normalizedThumbprint, string? keychainPath)
    {
        var findArgs = keychainPath != null
            ? $"find-certificate -a -Z {keychainPath}"
            : "find-certificate -a -Z";

        var (findExit, findOutput) = _processRunner.Run("security", findArgs);
        if (findExit != 0)
            return false;

        if (!findOutput.Contains(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
            return false;

        var deleteArgs = keychainPath != null
            ? $"delete-certificate -Z {normalizedThumbprint} {keychainPath}"
            : $"delete-certificate -Z {normalizedThumbprint}";

        var (deleteExit, _) = _processRunner.Run("security", deleteArgs);
        return deleteExit == 0;
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

        // Search and remove from System keychain
        removed += RemoveBySubjectFromKeychain(subjectMatch, SystemKeychain);

        // Search and remove from login keychain (no explicit path = default/login)
        removed += RemoveBySubjectFromKeychain(subjectMatch, keychainPath: null);

        return removed;
    }

    private int RemoveBySubjectFromKeychain(string subjectMatch, string? keychainPath)
    {
        int removed = 0;

        try
        {
            var findArgs = keychainPath != null
                ? $"find-certificate -a -c \"{subjectMatch}\" -Z {keychainPath}"
                : $"find-certificate -a -c \"{subjectMatch}\" -Z";

            var (exitCode, output) = _processRunner.Run("security", findArgs);

            if (exitCode != 0 || string.IsNullOrWhiteSpace(output))
                return 0;

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("SHA-1 hash:", StringComparison.OrdinalIgnoreCase))
                    continue;

                var hash = trimmed.Substring("SHA-1 hash:".Length).Trim();
                if (string.IsNullOrEmpty(hash))
                    continue;

                var deleteArgs = keychainPath != null
                    ? $"delete-certificate -Z {hash} {keychainPath}"
                    : $"delete-certificate -Z {hash}";

                var (deleteExit, _) = _processRunner.Run("security", deleteArgs);

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
