using NSubstitute;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class TrustStoreInterfaceTests
{
    [Fact]
    public void ITrustStore_ImportCaCertificate_CanBeMocked()
    {
        var mock = Substitute.For<ITrustStore>();
        mock.ImportCaCertificate(Arg.Any<X509Certificate2>()).Returns(true);

        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
        try
        {
            var result = mock.ImportCaCertificate(cert);

            Assert.True(result);
            mock.Received(1).ImportCaCertificate(cert);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ITrustStore_RemoveCaCertificate_CanBeMocked()
    {
        var mock = Substitute.For<ITrustStore>();
        mock.RemoveCaCertificate("ABC123").Returns(true);
        mock.RemoveCaCertificate("NOTFOUND").Returns(false);

        Assert.True(mock.RemoveCaCertificate("ABC123"));
        Assert.False(mock.RemoveCaCertificate("NOTFOUND"));
    }

    [Fact]
    public void ITrustStore_IsCertificateTrusted_CanBeMocked()
    {
        var mock = Substitute.For<ITrustStore>();
        mock.IsCertificateTrusted("TRUSTED_THUMB").Returns(true);
        mock.IsCertificateTrusted("UNTRUSTED_THUMB").Returns(false);

        Assert.True(mock.IsCertificateTrusted("TRUSTED_THUMB"));
        Assert.False(mock.IsCertificateTrusted("UNTRUSTED_THUMB"));
    }
}
