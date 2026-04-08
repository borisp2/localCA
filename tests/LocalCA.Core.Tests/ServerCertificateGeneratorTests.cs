using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class ServerCertificateGeneratorTests
{
    private readonly X509Certificate2 _caCert;
    private readonly RSA _caKey;

    public ServerCertificateGeneratorTests()
    {
        (_caCert, _caKey) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);
    }

    [Fact]
    public void ServerCert_ContainsExpectedSanDnsNames()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        var sanExtension = serverCert.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17"); // Subject Alternative Name

        Assert.NotNull(sanExtension);

        var sanText = sanExtension.Format(multiLine: true);
        var machineName = Environment.MachineName;

        Assert.Contains("localhost", sanText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(machineName, sanText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"{machineName}.local", sanText, StringComparison.OrdinalIgnoreCase);

        serverCert.Dispose();
    }

    [Fact]
    public void ServerCert_ContainsExpectedSanIpAddresses()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        var sanExtension = serverCert.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        Assert.NotNull(sanExtension);

        var sanText = sanExtension.Format(multiLine: true);

        Assert.Contains("127.0.0.1", sanText);
        // IPv6 loopback may be formatted as ::1 or 0:0:0:0:0:0:0:1 depending on platform
        Assert.True(
            sanText.Contains("::1") || sanText.Contains("0:0:0:0:0:0:0:1"),
            $"Expected IPv6 loopback in SAN but got: {sanText}");

        serverCert.Dispose();
    }

    [Fact]
    public void ServerCert_IsNotCa()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        var bc = serverCert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        Assert.NotNull(bc);
        Assert.False(bc.CertificateAuthority);

        serverCert.Dispose();
    }

    [Fact]
    public void ServerCert_HasServerAuthEku()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        var eku = serverCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        Assert.NotNull(eku);
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), o => o.Value == "1.3.6.1.5.5.7.3.1");

        serverCert.Dispose();
    }

    [Fact]
    public void PfxExport_RoundTrip_PreservesPrivateKey()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        // Export to PFX with empty password
        var pfxBytes = CertificateExporter.ExportPfx(serverCert, "");

        // Re-import
        var imported = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable);

        Assert.True(imported.HasPrivateKey);
        Assert.Equal(serverCert.Thumbprint, imported.Thumbprint);
        Assert.Equal(serverCert.Subject, imported.Subject);

        // Verify the private key is usable by signing and verifying data
        using var rsa = imported.GetRSAPrivateKey()!;
        var testData = new byte[] { 1, 2, 3, 4, 5 };
        var signature = rsa.SignData(testData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var pubKey = imported.GetRSAPublicKey()!;
        Assert.True(pubKey.VerifyData(testData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        imported.Dispose();
        serverCert.Dispose();
    }

    [Fact]
    public void PfxExport_RoundTrip_PreservesSans()
    {
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(_caCert, validDays: 30);

        var pfxBytes = CertificateExporter.ExportPfx(serverCert, "");
        var imported = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable);

        var sanExtension = imported.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        Assert.NotNull(sanExtension);
        var sanText = sanExtension.Format(multiLine: true);

        Assert.Contains("localhost", sanText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("127.0.0.1", sanText);
        Assert.True(
            sanText.Contains("::1") || sanText.Contains("0:0:0:0:0:0:0:1"),
            $"Expected IPv6 loopback in SAN but got: {sanText}");

        imported.Dispose();
        serverCert.Dispose();
    }
}
