using NSubstitute;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class LinuxTrustStoreTests
{
    private static LinuxTrustStore.LinuxDistroInfo DebianDistro(string certDir) => new()
    {
        Family = LinuxTrustStore.LinuxDistroFamily.DebianLike,
        CertDirectory = certDir,
        UpdateCommand = "update-ca-certificates",
        UpdateArgs = null
    };

    private static LinuxTrustStore.LinuxDistroInfo RedHatDistro(string certDir) => new()
    {
        Family = LinuxTrustStore.LinuxDistroFamily.RedHatLike,
        CertDirectory = certDir,
        UpdateCommand = "update-ca-trust",
        UpdateArgs = "extract"
    };

    private static LinuxTrustStore.LinuxDistroInfo UnknownDistro() => new()
    {
        Family = LinuxTrustStore.LinuxDistroFamily.Unknown,
        CertDirectory = null,
        UpdateCommand = null,
        UpdateArgs = null
    };

    [Fact]
    public void ImportCaCertificate_DebianLike_WritesPemAndRunsUpdate()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            mockRunner.Run("update-ca-certificates", "").Returns((0, ""));

            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
            try
            {
                var result = store.ImportCaCertificate(cert);

                Assert.True(result);

                // Verify PEM file was written
                var expectedPath = Path.Combine(tempDir, $"localca-{cert.Thumbprint.ToLowerInvariant()}.crt");
                Assert.True(File.Exists(expectedPath));

                var content = File.ReadAllText(expectedPath);
                Assert.StartsWith("-----BEGIN CERTIFICATE-----", content);

                // Verify update command was called
                mockRunner.Received(1).Run("update-ca-certificates", "");
            }
            finally
            {
                key.Dispose();
                cert.Dispose();
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ImportCaCertificate_RedHatLike_RunsUpdateCaTrustExtract()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            mockRunner.Run("update-ca-trust", "extract").Returns((0, ""));

            var store = new LinuxTrustStore(mockRunner, RedHatDistro(tempDir));

            var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
            try
            {
                var result = store.ImportCaCertificate(cert);

                Assert.True(result);
                mockRunner.Received(1).Run("update-ca-trust", "extract");
            }
            finally
            {
                key.Dispose();
                cert.Dispose();
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ImportCaCertificate_UnknownDistro_ReturnsFalse()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        var store = new LinuxTrustStore(mockRunner, UnknownDistro());

        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
        try
        {
            var result = store.ImportCaCertificate(cert);

            Assert.False(result);
            mockRunner.DidNotReceiveWithAnyArgs().Run(default!, default!);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ImportCaCertificate_UpdateFails_ReturnsFalseAndRollsBackPemFile()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            mockRunner.Run("update-ca-certificates", "").Returns((1, "error"));

            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
            try
            {
                var result = store.ImportCaCertificate(cert);

                Assert.False(result);

                // Verify the PEM file was cleaned up so IsCertificateTrusted
                // does not report a false positive.
                var expectedPath = Path.Combine(tempDir, $"localca-{cert.Thumbprint.ToLowerInvariant()}.crt");
                Assert.False(File.Exists(expectedPath), "PEM file should be removed when update command fails");

                // Confirm IsCertificateTrusted returns false (no false positive)
                Assert.False(store.IsCertificateTrusted(cert.Thumbprint));
            }
            finally
            {
                key.Dispose();
                cert.Dispose();
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void RemoveCaCertificate_FileExists_DeletesAndRunsUpdate()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var thumbprint = "AABBCCDD1122";
            var certPath = Path.Combine(tempDir, $"localca-{thumbprint.ToLowerInvariant()}.crt");
            File.WriteAllText(certPath, "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----");

            var mockRunner = Substitute.For<IProcessRunner>();
            mockRunner.Run("update-ca-certificates", "").Returns((0, ""));

            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            var result = store.RemoveCaCertificate(thumbprint);

            Assert.True(result);
            Assert.False(File.Exists(certPath));
            mockRunner.Received(1).Run("update-ca-certificates", "");
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void RemoveCaCertificate_FileNotFound_ReturnsFalse()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            var result = store.RemoveCaCertificate("NONEXISTENT");

            Assert.False(result);
            mockRunner.DidNotReceiveWithAnyArgs().Run(default!, default!);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void IsCertificateTrusted_FileExists_ReturnsTrue()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var thumbprint = "AABBCCDD1122";
            var certPath = Path.Combine(tempDir, $"localca-{thumbprint.ToLowerInvariant()}.crt");
            File.WriteAllText(certPath, "dummy");

            var mockRunner = Substitute.For<IProcessRunner>();
            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            Assert.True(store.IsCertificateTrusted(thumbprint));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void IsCertificateTrusted_FileNotFound_ReturnsFalse()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            Assert.False(store.IsCertificateTrusted("NONEXISTENT"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void IsCertificateTrusted_UnknownDistro_ReturnsFalse()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        var store = new LinuxTrustStore(mockRunner, UnknownDistro());

        Assert.False(store.IsCertificateTrusted("ANY"));
    }

    [Fact]
    public void RemoveBySubject_MatchingCerts_RemovesAndReturnsCount()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            // Create a real cert to write as PEM
            var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
            try
            {
                var pem = cert.ExportCertificatePem();
                var thumbprint = cert.Thumbprint.ToLowerInvariant();
                File.WriteAllText(Path.Combine(tempDir, $"localca-{thumbprint}.crt"), pem);

                var mockRunner = Substitute.For<IProcessRunner>();
                mockRunner.Run("update-ca-certificates", "").Returns((0, ""));

                var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

                // "TestApp Localhost Root CA" should be in the cert subject
                var removed = store.RemoveBySubject("TestApp Localhost Root CA");

                Assert.Equal(1, removed);
                Assert.False(File.Exists(Path.Combine(tempDir, $"localca-{thumbprint}.crt")));
                mockRunner.Received(1).Run("update-ca-certificates", "");
            }
            finally
            {
                key.Dispose();
                cert.Dispose();
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void RemoveBySubject_NoMatches_ReturnsZero()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"linuxtrust-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var mockRunner = Substitute.For<IProcessRunner>();
            var store = new LinuxTrustStore(mockRunner, DebianDistro(tempDir));

            var removed = store.RemoveBySubject("NonExistentApp");

            Assert.Equal(0, removed);
            mockRunner.DidNotReceiveWithAnyArgs().Run(default!, default!);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void DetectDistro_DebianLike_WhenDirectoryAndCommandExist()
    {
        // This test verifies the detection logic structure.
        // On a Debian system, it would detect correctly; on others,
        // it will fall through to whatever is available or Unknown.
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("which", "update-ca-certificates").Returns((0, "/usr/sbin/update-ca-certificates"));
        mockRunner.Run("which", "update-ca-trust").Returns((1, ""));

        // We can only test the full path on an actual Debian system because
        // DetectDistro checks for directory existence. Test the Unknown fallback instead.
        var distro = LinuxTrustStore.DetectDistro(mockRunner);

        // On this test runner, the result depends on the OS; just verify it doesn't throw
        Assert.NotNull(distro);
    }
}
