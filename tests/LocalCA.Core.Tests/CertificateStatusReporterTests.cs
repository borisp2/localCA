using NSubstitute;

namespace LocalCA.Core.Tests;

public class CertificateStatusReporterTests
{
    [Fact]
    public void GetStatus_WithFullInstall_ReportsAllArtifactsPresent()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "StatusTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir);

            Assert.True(report.CaCertificate.Exists);
            Assert.True(report.ServerCertificate.Exists);
            Assert.True(report.CaKeyExists);
            Assert.True(report.ServerKeyExists);
            Assert.True(report.PfxExists);
            Assert.True(report.FullchainExists);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_WithFullInstall_ReportsCaCertMetadata()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "MetaTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir);

            Assert.Contains("MetaTest Localhost Root CA", report.CaCertificate.Subject);
            Assert.NotNull(report.CaCertificate.Thumbprint);
            Assert.True(report.CaCertificate.NotBefore < DateTime.UtcNow);
            Assert.True(report.CaCertificate.NotAfter > DateTime.UtcNow);
            Assert.Equal(true, report.CaCertificate.IsCa);
            Assert.True(report.CaCertificate.DaysRemaining > 0);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_WithFullInstall_ReportsServerCertMetadata()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "MetaTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir);

            Assert.Contains("localhost", report.ServerCertificate.Subject!);
            Assert.NotNull(report.ServerCertificate.Thumbprint);
            Assert.True(report.ServerCertificate.NotBefore < DateTime.UtcNow);
            Assert.True(report.ServerCertificate.NotAfter > DateTime.UtcNow);
            Assert.Contains("localhost", report.ServerCertificate.DnsNames);
            Assert.Contains("127.0.0.1", report.ServerCertificate.IpAddresses);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_EmptyDirectory_ReportsMissingArtifacts()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var report = CertificateStatusReporter.GetStatus(tempDir);

            Assert.False(report.CaCertificate.Exists);
            Assert.False(report.ServerCertificate.Exists);
            Assert.False(report.CaKeyExists);
            Assert.False(report.ServerKeyExists);
            Assert.False(report.PfxExists);
            Assert.False(report.FullchainExists);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_WithTrustStore_ChecksTrustStatus()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "TrustTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var mockTrustStore = Substitute.For<ITrustStore>();
            mockTrustStore.IsCertificateTrusted(Arg.Any<string>()).Returns(true);

            var report = CertificateStatusReporter.GetStatus(tempDir, mockTrustStore);

            Assert.True(report.CaCertificate.IsTrusted);
            mockTrustStore.Received(1).IsCertificateTrusted(Arg.Any<string>());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_WithoutTrustStore_TrustStatusIsNull()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "NoTrust",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir, trustStore: null);

            Assert.Null(report.CaCertificate.IsTrusted);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void FormatReport_ContainsExpectedSections()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "FormatTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir);
            var text = report.FormatReport();

            Assert.Contains("LocalCA Status", text);
            Assert.Contains("Artifacts:", text);
            Assert.Contains("CA Certificate:", text);
            Assert.Contains("Server Certificate:", text);
            Assert.Contains("Subject:", text);
            Assert.Contains("Thumbprint:", text);
            Assert.Contains("Valid from:", text);
            Assert.Contains("Valid until:", text);
            Assert.Contains("DNS SANs:", text);
            Assert.Contains("IP SANs:", text);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void GetStatus_CaKeySizeIs4096()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-status-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "KeySize",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, cmd.Execute());

            var report = CertificateStatusReporter.GetStatus(tempDir);

            Assert.Equal(4096, report.CaCertificate.KeySizeBits);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
