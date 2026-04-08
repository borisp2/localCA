using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class CertificateVerifierTests
{
    [Fact]
    public void Verify_WithValidCaAndServerCert_ReturnsValid()
    {
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);
        try
        {
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);
            try
            {
                var result = CertificateVerifier.Verify(caCert, serverCert);

                Assert.True(result.IsValid);
                Assert.Empty(result.Errors);
                Assert.NotEmpty(result.Details);
                Assert.Contains("All checks passed", result.Summary);
            }
            finally
            {
                serverCert.Dispose();
            }
        }
        finally
        {
            caKey.Dispose();
            caCert.Dispose();
        }
    }

    [Fact]
    public void Verify_ChecksIssuerMatchesCASubject()
    {
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);
        try
        {
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);
            try
            {
                var result = CertificateVerifier.Verify(caCert, serverCert);

                Assert.Contains(result.Details,
                    d => d.Contains("issuer matches CA subject"));
            }
            finally
            {
                serverCert.Dispose();
            }
        }
        finally
        {
            caKey.Dispose();
            caCert.Dispose();
        }
    }

    [Fact]
    public void Verify_ReportsServerAuthEKU()
    {
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);
        try
        {
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);
            try
            {
                var result = CertificateVerifier.Verify(caCert, serverCert);

                Assert.Contains(result.Details,
                    d => d.Contains("serverAuth"));
            }
            finally
            {
                serverCert.Dispose();
            }
        }
        finally
        {
            caKey.Dispose();
            caCert.Dispose();
        }
    }

    [Fact]
    public void Verify_ReportsSANs()
    {
        var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);
        try
        {
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(caCert, validDays: 30);
            try
            {
                var result = CertificateVerifier.Verify(caCert, serverCert);

                Assert.Contains(result.Details,
                    d => d.Contains("SANs:") && d.Contains("localhost"));
            }
            finally
            {
                serverCert.Dispose();
            }
        }
        finally
        {
            caKey.Dispose();
            caCert.Dispose();
        }
    }

    [Fact]
    public void Verify_FromDisk_WithValidArtifacts_ReturnsValid()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-verify-test-{Guid.NewGuid():N}");
        try
        {
            // Generate certs and write artifacts
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "VerifyTest",
                CaValidDays = 365,
                ServerValidDays = 30,
                Force = false,
                Verbose = false
            };
            Assert.Equal(0, cmd.Execute());

            var result = CertificateVerifier.Verify(tempDir);

            Assert.True(result.IsValid);
            Assert.Empty(result.Errors);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Verify_FromDisk_MissingCaCert_ReturnsInvalid()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-verify-test-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var result = CertificateVerifier.Verify(tempDir);

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("CA certificate not found"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Verify_FromDisk_MissingServerCert_ReturnsInvalid()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-verify-test-{Guid.NewGuid():N}");
        try
        {
            // Create CA only
            DirectoryLayout.EnsureDirectories(tempDir);
            var (caCert, caKey) = CertificateAuthority.CreateRootCa("TestApp", validDays: 365, keySizeBits: 2048);
            File.WriteAllText(
                Path.Combine(tempDir, "certs", "ca.crt"),
                CertificateExporter.ExportCertificatePem(caCert));
            caKey.Dispose();
            caCert.Dispose();

            var result = CertificateVerifier.Verify(tempDir);

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("Server certificate not found"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Verify_WithMismatchedCerts_ReportsIssuerMismatch()
    {
        // Create two independent CAs and use server cert from one with CA from another
        var (ca1Cert, ca1Key) = CertificateAuthority.CreateRootCa("CA-One", validDays: 365, keySizeBits: 2048);
        var (ca2Cert, ca2Key) = CertificateAuthority.CreateRootCa("CA-Two", validDays: 365, keySizeBits: 2048);

        try
        {
            var serverCert = ServerCertificateGenerator.CreateServerCertificate(ca1Cert, validDays: 30);
            try
            {
                // Verify against the WRONG CA
                var result = CertificateVerifier.Verify(ca2Cert, serverCert);

                Assert.False(result.IsValid);
                Assert.Contains(result.Errors,
                    e => e.Contains("does not match CA subject"));
            }
            finally
            {
                serverCert.Dispose();
            }
        }
        finally
        {
            ca1Key.Dispose();
            ca1Cert.Dispose();
            ca2Key.Dispose();
            ca2Cert.Dispose();
        }
    }
}
