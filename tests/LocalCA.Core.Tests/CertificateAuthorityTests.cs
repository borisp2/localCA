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
}
