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

        // Export and re-import so the cert is detached from the ephemeral key
        var exported = RSA.Create();
        exported.ImportPkcs8PrivateKey(rsa.ExportPkcs8PrivateKey(), out _);

        return (cert, exported);
    }
}
