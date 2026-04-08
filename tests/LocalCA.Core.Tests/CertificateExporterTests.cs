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

        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.Contains("-----END PRIVATE KEY-----", pem);

        key.Dispose();
        cert.Dispose();
    }

    [Fact]
    public void ExportPrivateKeyPem_RoundtripsViaPkcs8()
    {
        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);

        var pem = CertificateExporter.ExportPrivateKeyPem(key);

        // Re-import the PKCS#8 PEM and verify it can sign data
        var reimported = RSA.Create();
        reimported.ImportFromPem(pem);

        var data = new byte[] { 1, 2, 3, 4 };
        var signature = reimported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        reimported.Dispose();
        key.Dispose();
        cert.Dispose();
    }

    [Fact]
    public void ExportPrivateKeyPem_WorksWithPfxReimportedKey()
    {
        // Simulates the Windows CNG scenario: load cert from PFX, then export key
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", keySizeBits: 2048);
        var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);

        // Re-import from PFX (on Windows this creates a CNG-backed key)
        var pfxBytes = serverCert.Export(X509ContentType.Pfx, "");
        var reimported = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.Exportable);
        var rsaKey = reimported.GetRSAPrivateKey()!;

        // This must not throw — the whole point of the PKCS#8 fix
        var pem = CertificateExporter.ExportPrivateKeyPem(rsaKey);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.Contains("-----END PRIVATE KEY-----", pem);

        reimported.Dispose();
        serverCert.Dispose();
        caKey.Dispose();
        caCert.Dispose();
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
        Assert.Contains("-----BEGIN PRIVATE KEY-----", fullchain);

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
