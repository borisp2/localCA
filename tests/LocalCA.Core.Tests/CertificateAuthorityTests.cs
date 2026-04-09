using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class CertificateAuthorityTests
{
    [Fact]
    public void CreateRootCa_ReturnsValidSelfSignedCertificate()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);

        try
        {
            Assert.Contains("TestApp Localhost Root CA", cert.Subject);
            Assert.Contains("C=XX", cert.Subject);
            Assert.True(cert.NotAfter > DateTime.UtcNow.AddDays(360));
            Assert.Equal("RSA", cert.PublicKey.Oid.FriendlyName);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void CreateRootCa_HasBasicConstraintsCa()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        try
        {
            var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            Assert.NotNull(bc);
            Assert.True(bc.CertificateAuthority);
            Assert.True(bc.Critical);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void CreateRootCa_HasKeyUsageCertSignAndCrlSign()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        try
        {
            var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            Assert.NotNull(ku);
            Assert.True(ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign));
            Assert.True(ku.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign));
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void CreateRootCa_PrivateKeyIsExportableToPkcs8()
    {
        // Validates the Windows-safe lifecycle: the returned RSA key must
        // support ExportPkcs8PrivateKey (fails on Windows/CNG without the
        // PFX round-trip + EphemeralKeySet fix).
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        try
        {
            var pkcs8 = key.ExportPkcs8PrivateKey();
            Assert.NotNull(pkcs8);
            Assert.True(pkcs8.Length > 0);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void CreateRootCa_CertPrivateKeyIsExportableToPem()
    {
        // The cert itself must carry an exportable private key so that
        // GetRSAPrivateKey() → ExportPkcs8PrivateKey() works (Windows CNG path).
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        try
        {
            Assert.True(cert.HasPrivateKey);
            var certKey = cert.GetRSAPrivateKey();
            Assert.NotNull(certKey);
            var pem = CertificateExporter.ExportPrivateKeyPem(certKey!);
            Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void CreateRootCa_KeyAndCertAreIndependent()
    {
        // The returned key must be usable independently of the cert's lifetime.
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        // Dispose the cert first, then verify the standalone key still works
        cert.Dispose();

        var pkcs8 = key.ExportPkcs8PrivateKey();
        Assert.True(pkcs8.Length > 0);

        var data = new byte[] { 1, 2, 3, 4 };
        var sig = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.NotEmpty(sig);

        key.Dispose();
    }
}
