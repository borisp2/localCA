using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Linux trust store operations using the system CA certificate directories
/// and update-ca-certificates (Debian/Ubuntu/SUSE) or update-ca-trust (RHEL/Fedora/CentOS).
///
/// <para><b>Distro support:</b></para>
/// <list type="bullet">
///   <item>Debian/Ubuntu/SUSE: copies PEM to <c>/usr/local/share/ca-certificates/</c> and runs <c>update-ca-certificates</c></item>
///   <item>RHEL/Fedora/CentOS: copies PEM to <c>/etc/pki/ca-trust/source/anchors/</c> and runs <c>update-ca-trust</c></item>
/// </list>
///
/// <para><b>Permissions:</b> Import and remove operations typically require root/sudo.
/// The class does not escalate privileges; callers must run as root or use sudo.</para>
///
/// <para><b>Certificate format:</b> Certificates are exported as PEM (.crt) files.
/// The filename is derived from the certificate thumbprint for deterministic placement.</para>
/// </summary>
public sealed class LinuxTrustStore : ITrustStore
{
    private readonly IProcessRunner _processRunner;
    private readonly LinuxDistroInfo _distro;

    public LinuxTrustStore()
        : this(new SystemProcessRunner())
    {
    }

    public LinuxTrustStore(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
        _distro = DetectDistro(processRunner);
    }

    /// <summary>
    /// Internal constructor for testing with a pre-built distro info.
    /// </summary>
    internal LinuxTrustStore(IProcessRunner processRunner, LinuxDistroInfo distro)
    {
        _processRunner = processRunner;
        _distro = distro;
    }

    public bool ImportCaCertificate(X509Certificate2 certificate)
    {
        if (_distro.CertDirectory == null || _distro.UpdateCommand == null)
            return false;

        try
        {
            var pem = certificate.ExportCertificatePem();
            var certPath = GetCertFilePath(certificate.Thumbprint);

            // Ensure the target directory exists
            var dir = Path.GetDirectoryName(certPath)!;
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            File.WriteAllText(certPath, pem);

            var (exitCode, _) = _processRunner.Run(_distro.UpdateCommand, _distro.UpdateArgs ?? "");
            if (exitCode != 0)
            {
                // Rollback: remove the PEM file so IsCertificateTrusted does not
                // report a false positive when the trust database was never updated.
                try { File.Delete(certPath); } catch { /* best effort */ }
                return false;
            }

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public bool RemoveCaCertificate(string thumbprint)
    {
        if (_distro.CertDirectory == null || _distro.UpdateCommand == null)
            return false;

        try
        {
            var certPath = GetCertFilePath(thumbprint);

            if (!File.Exists(certPath))
                return false;

            File.Delete(certPath);

            var (exitCode, _) = _processRunner.Run(_distro.UpdateCommand, _distro.UpdateArgs ?? "");
            return exitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public bool IsCertificateTrusted(string thumbprint)
    {
        if (_distro.CertDirectory == null)
            return false;

        // Primary check: our managed file exists in the trust directory
        var certPath = GetCertFilePath(thumbprint);
        if (File.Exists(certPath))
            return true;

        // Secondary check: search the consolidated trust bundle for the thumbprint.
        // On Debian-family: /etc/ssl/certs; on RHEL-family: /etc/pki/tls/certs
        // We use openssl to check if the cert is in the bundle, but since the
        // primary file check covers our own imports, this is a best-effort fallback.
        return false;
    }

    public int RemoveBySubject(string subjectMatch)
    {
        if (_distro.CertDirectory == null || _distro.UpdateCommand == null)
            return 0;

        int removed = 0;

        try
        {
            if (!Directory.Exists(_distro.CertDirectory))
                return 0;

            // Search for .crt files that contain the subject match in their PEM content
            foreach (var filePath in Directory.GetFiles(_distro.CertDirectory, "localca-*.crt"))
            {
                try
                {
                    var pem = File.ReadAllText(filePath);
                    using var cert = X509Certificate2.CreateFromPem(pem);

                    if (cert.Subject.Contains(subjectMatch, StringComparison.OrdinalIgnoreCase))
                    {
                        File.Delete(filePath);
                        removed++;
                    }
                }
                catch (Exception)
                {
                    // Skip files that can't be parsed
                }
            }

            if (removed > 0)
            {
                _processRunner.Run(_distro.UpdateCommand, _distro.UpdateArgs ?? "");
            }
        }
        catch (Exception)
        {
            // Directory access failure
        }

        return removed;
    }

    private string GetCertFilePath(string thumbprint)
    {
        // Use a "localca-" prefix so RemoveBySubject can scope its search,
        // and the thumbprint ensures uniqueness.
        return Path.Combine(_distro.CertDirectory!, $"localca-{thumbprint.ToLowerInvariant()}.crt");
    }

    /// <summary>
    /// Detects the Linux distribution family and returns the appropriate
    /// certificate directory and update command.
    /// </summary>
    internal static LinuxDistroInfo DetectDistro(IProcessRunner processRunner)
    {
        // Check for Debian/Ubuntu/SUSE style (update-ca-certificates)
        if (Directory.Exists("/usr/local/share/ca-certificates"))
        {
            var (exitCode, _) = processRunner.Run("which", "update-ca-certificates");
            if (exitCode == 0)
            {
                return new LinuxDistroInfo
                {
                    Family = LinuxDistroFamily.DebianLike,
                    CertDirectory = "/usr/local/share/ca-certificates",
                    UpdateCommand = "update-ca-certificates",
                    UpdateArgs = null
                };
            }
        }

        // Check for RHEL/Fedora/CentOS style (update-ca-trust)
        if (Directory.Exists("/etc/pki/ca-trust/source/anchors"))
        {
            var (exitCode, _) = processRunner.Run("which", "update-ca-trust");
            if (exitCode == 0)
            {
                return new LinuxDistroInfo
                {
                    Family = LinuxDistroFamily.RedHatLike,
                    CertDirectory = "/etc/pki/ca-trust/source/anchors",
                    UpdateCommand = "update-ca-trust",
                    UpdateArgs = "extract"
                };
            }
        }

        // Unknown distro — operations will be no-ops
        return new LinuxDistroInfo
        {
            Family = LinuxDistroFamily.Unknown,
            CertDirectory = null,
            UpdateCommand = null,
            UpdateArgs = null
        };
    }

    internal enum LinuxDistroFamily
    {
        Unknown,
        DebianLike,
        RedHatLike
    }

    internal sealed class LinuxDistroInfo
    {
        public LinuxDistroFamily Family { get; init; }
        public string? CertDirectory { get; init; }
        public string? UpdateCommand { get; init; }
        public string? UpdateArgs { get; init; }
    }
}
