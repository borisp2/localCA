using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Abstraction for OS certificate trust store operations.
/// </summary>
public interface ITrustStore
{
    /// <summary>
    /// Import a CA certificate into the trust store.
    /// Returns true if the certificate was imported successfully.
    /// </summary>
    bool ImportCaCertificate(X509Certificate2 certificate);

    /// <summary>
    /// Remove a CA certificate from the trust store by thumbprint.
    /// Returns true if the certificate was found and removed.
    /// </summary>
    bool RemoveCaCertificate(string thumbprint);

    /// <summary>
    /// Check whether a certificate with the given thumbprint is currently trusted.
    /// </summary>
    bool IsCertificateTrusted(string thumbprint);

    /// <summary>
    /// Remove CA certificates from the trust store matching a subject substring.
    /// Used as a fallback when the thumbprint is not available.
    /// Returns the number of certificates removed.
    /// </summary>
    int RemoveBySubject(string subjectMatch);
}
