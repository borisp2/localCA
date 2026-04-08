using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Result of a certificate verification operation.
/// </summary>
public sealed class VerifyResult
{
    public bool IsValid { get; init; }
    public string Summary { get; init; } = "";
    public IReadOnlyList<string> Details { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Validates a server certificate against a CA certificate,
/// checking chain trust, validity, key usage, and SANs.
/// </summary>
public static class CertificateVerifier
{
    /// <summary>
    /// Verify the server certificate at the given rootDir was issued by the CA
    /// and passes chain/validity checks.
    /// </summary>
    public static VerifyResult Verify(string rootDir)
    {
        var caCertPath = Path.Combine(rootDir, "certs", "ca.crt");
        var serverCertPath = Path.Combine(rootDir, "server", "localhost.crt");

        var details = new List<string>();
        var errors = new List<string>();

        // Check files exist
        if (!File.Exists(caCertPath))
        {
            errors.Add($"CA certificate not found: {caCertPath}");
            return new VerifyResult
            {
                IsValid = false,
                Summary = "Verification failed: CA certificate not found.",
                Details = details,
                Errors = errors
            };
        }

        if (!File.Exists(serverCertPath))
        {
            errors.Add($"Server certificate not found: {serverCertPath}");
            return new VerifyResult
            {
                IsValid = false,
                Summary = "Verification failed: server certificate not found.",
                Details = details,
                Errors = errors
            };
        }

        X509Certificate2 caCert;
        X509Certificate2 serverCert;

        try
        {
            caCert = new X509Certificate2(caCertPath);
        }
        catch (Exception ex)
        {
            errors.Add($"Failed to load CA certificate: {ex.Message}");
            return new VerifyResult
            {
                IsValid = false,
                Summary = "Verification failed: could not load CA certificate.",
                Details = details,
                Errors = errors
            };
        }

        try
        {
            serverCert = new X509Certificate2(serverCertPath);
        }
        catch (Exception ex)
        {
            caCert.Dispose();
            errors.Add($"Failed to load server certificate: {ex.Message}");
            return new VerifyResult
            {
                IsValid = false,
                Summary = "Verification failed: could not load server certificate.",
                Details = details,
                Errors = errors
            };
        }

        try
        {
            return VerifyCertificates(caCert, serverCert, details, errors);
        }
        finally
        {
            caCert.Dispose();
            serverCert.Dispose();
        }
    }

    /// <summary>
    /// Verify an in-memory server certificate against a CA certificate.
    /// </summary>
    public static VerifyResult Verify(X509Certificate2 caCert, X509Certificate2 serverCert)
    {
        var details = new List<string>();
        var errors = new List<string>();
        return VerifyCertificates(caCert, serverCert, details, errors);
    }

    private static VerifyResult VerifyCertificates(
        X509Certificate2 caCert,
        X509Certificate2 serverCert,
        List<string> details,
        List<string> errors)
    {
        // 1. Check CA is actually a CA
        var caBasicConstraints = caCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        if (caBasicConstraints?.CertificateAuthority == true)
            details.Add("CA certificate has BasicConstraints CA=true.");
        else
            errors.Add("CA certificate is not marked as a Certificate Authority.");

        // 2. Check server cert is NOT a CA
        var serverBasicConstraints = serverCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        if (serverBasicConstraints?.CertificateAuthority == false)
            details.Add("Server certificate has BasicConstraints CA=false.");
        else
            errors.Add("Server certificate should have BasicConstraints CA=false.");

        // 3. Check server cert validity period
        var now = DateTime.UtcNow;
        if (serverCert.NotBefore <= now && serverCert.NotAfter >= now)
            details.Add($"Server certificate is within its validity period ({serverCert.NotBefore:yyyy-MM-dd} to {serverCert.NotAfter:yyyy-MM-dd}).");
        else
            errors.Add($"Server certificate is outside its validity period ({serverCert.NotBefore:yyyy-MM-dd} to {serverCert.NotAfter:yyyy-MM-dd}).");

        // 4. Check CA cert validity period
        if (caCert.NotBefore <= now && caCert.NotAfter >= now)
            details.Add($"CA certificate is within its validity period ({caCert.NotBefore:yyyy-MM-dd} to {caCert.NotAfter:yyyy-MM-dd}).");
        else
            errors.Add($"CA certificate is outside its validity period ({caCert.NotBefore:yyyy-MM-dd} to {caCert.NotAfter:yyyy-MM-dd}).");

        // 5. Check issuer/subject relationship
        if (serverCert.Issuer == caCert.Subject)
            details.Add($"Server certificate issuer matches CA subject: {caCert.Subject}");
        else
            errors.Add($"Server certificate issuer ({serverCert.Issuer}) does not match CA subject ({caCert.Subject}).");

        // 6. Chain validation using X509Chain
        bool chainValid = false;
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.ExtraStore.Add(caCert);

            chainValid = chain.Build(serverCert);

            if (chainValid)
            {
                details.Add("Certificate chain validation succeeded.");
            }
            else
            {
                // Report chain status but don't necessarily fail for UntrustedRoot
                // since the CA may not be in the system trust store
                var statusFlags = chain.ChainStatus
                    .Select(s => s.Status)
                    .Distinct()
                    .ToList();

                bool onlyUntrustedRoot = statusFlags.Count == 1
                    && statusFlags[0] == X509ChainStatusFlags.UntrustedRoot;

                if (onlyUntrustedRoot)
                {
                    details.Add("Certificate chain is valid (CA not in system trust store — expected for local CA).");
                    chainValid = true; // This is OK for a local CA
                }
                else
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                            errors.Add($"Chain error: {status.Status} — {status.StatusInformation}");
                    }
                }
            }
        }

        // 7. Check server cert has serverAuth EKU
        var eku = serverCert.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (eku != null)
        {
            bool hasServerAuth = eku.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(o => o.Value == "1.3.6.1.5.5.7.3.1");

            if (hasServerAuth)
                details.Add("Server certificate has serverAuth extended key usage.");
            else
                errors.Add("Server certificate is missing serverAuth extended key usage.");
        }
        else
        {
            errors.Add("Server certificate has no Enhanced Key Usage extension.");
        }

        // 8. Check SANs
        var san = serverCert.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();

        if (san != null)
        {
            var dnsNames = san.EnumerateDnsNames().ToList();
            var ips = san.EnumerateIPAddresses().ToList();

            if (dnsNames.Count > 0 || ips.Count > 0)
                details.Add($"SANs: DNS=[{string.Join(", ", dnsNames)}] IP=[{string.Join(", ", ips)}]");
            else
                errors.Add("Server certificate has a SAN extension but no DNS names or IP addresses.");
        }
        else
        {
            errors.Add("Server certificate has no Subject Alternative Name extension.");
        }

        bool isValid = errors.Count == 0 && chainValid;
        string summary = isValid
            ? "All checks passed. Server certificate is valid and was issued by the CA."
            : $"Verification completed with {errors.Count} error(s).";

        return new VerifyResult
        {
            IsValid = isValid,
            Summary = summary,
            Details = details,
            Errors = errors
        };
    }
}
