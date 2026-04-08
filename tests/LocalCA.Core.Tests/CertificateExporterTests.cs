using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class CertificateExporterTests
{
    [Fact]
    public void ExportCertificatePem_ContainsPemMarkers()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        var pem = CertificateExporter.ExportCertificatePem(cert);

        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
        Assert.Contains("-----END CERTIFICATE-----", pem);

        key.Dispose();
        cert.Dispose();
    }

    [Fact]
    public void ExportPrivateKeyPem_ContainsPemMarkers()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        var pem = CertificateExporter.ExportPrivateKeyPem(key);

        Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", pem);
        Assert.Contains("-----END RSA PRIVATE KEY-----", pem);

        key.Dispose();
        cert.Dispose();
    }

    [Fact]
    public void ExportFullchainPem_ContainsServerAndCaCerts()
    {
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);

        var fullchain = CertificateExporter.ExportFullchainPem(serverCert, caCert);

        // Should contain two certificates and one private key
        var certCount = fullchain.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.Equal(2, certCount);
        Assert.Contains("-----BEGIN RSA PRIVATE KEY-----", fullchain);

        serverCert.Dispose();
        caKey.Dispose();
        caCert.Dispose();
    }

    [Fact]
    public void WriteArtifacts_CreatesExpectedFiles()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-test-{Guid.NewGuid():N}");
        try
        {
            DirectoryLayout.EnsureDirectories(tempDir);

            var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);

            CertificateExporter.WriteArtifacts(tempDir, caCert, caKey, serverCert);

            Assert.True(File.Exists(Path.Combine(tempDir, "private", "ca.key")));
            Assert.True(File.Exists(Path.Combine(tempDir, "certs", "ca.crt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.key")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.crt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.pfx")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost-fullchain.pem")));

            // Verify PFX can be loaded
            var pfxBytes = File.ReadAllBytes(Path.Combine(tempDir, "server", "localhost.pfx"));
            var loaded = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable);
            Assert.True(loaded.HasPrivateKey);
            loaded.Dispose();

            serverCert.Dispose();
            caKey.Dispose();
            caCert.Dispose();
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
