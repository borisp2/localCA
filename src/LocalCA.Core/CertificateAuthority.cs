using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Generates a self-signed Root CA certificate and private key.
/// </summary>
public static class CertificateAuthority
{
    public static (X509Certificate2 Certificate, RSA PrivateKey) CreateRootCa(
        string appName = "MyApp",
        int validDays = 3650,
        int keySizeBits = 4096)
    {
        using var rsa = RSA.Create(keySizeBits);

        var subject = new X500DistinguishedName(
            $"CN={appName} Localhost Root CA, O={appName}, C=XX");

        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 1,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(validDays);

        var cert = request.CreateSelfSigned(notBefore, notAfter);

        // PFX round-trip so both cert and key are fully portable.
        // EphemeralKeySet keeps the private key in memory only (no Windows
        // key-store persistence), avoiding CNG non-exportable handle issues.
        var pfxBytes = cert.Export(X509ContentType.Pfx, "");
        var portableCert = new X509Certificate2(
            pfxBytes, "",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        // Extract a standalone RSA key so it can be used/disposed independently of the cert
        var certKey = portableCert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("CA certificate lost its private key during PFX round-trip.");
        var exported = RSA.Create();
        exported.ImportPkcs8PrivateKey(certKey.ExportPkcs8PrivateKey(), out _);

        return (portableCert, exported);
    }
}
