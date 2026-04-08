using LocalCA.Core;
using NSubstitute;

namespace LocalCA.Cli.Tests;

public class RenewCommandTests
{
    private string SetupInstalledCA()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-renew-test-{Guid.NewGuid():N}");
        var cmd = new InstallCommand
        {
            RootDir = tempDir,
            AppName = "TestApp",
            CaValidDays = 365,
            ServerValidDays = 30,
            Force = false,
            Verbose = false
        };
        cmd.Execute();
        return tempDir;
    }

    private void Cleanup(string dir)
    {
        if (Directory.Exists(dir))
            Directory.Delete(dir, recursive: true);
    }

    [Fact]
    public void Renew_WithForce_RegeneratesServerCert()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var originalCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));
            var originalPfx = File.ReadAllBytes(Path.Combine(tempDir, "server", "localhost.pfx"));

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                ServerValidDays = 30,
                Force = true,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);

            // New cert should be different
            var newCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));
            Assert.NotEqual(originalCert, newCert);

            // All artifacts should exist
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.crt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.key")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.pfx")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost-fullchain.pem")));
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_WithoutForce_SkipsWhenNotExpiring()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var originalCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                RenewThresholdDays = 1, // cert has 30 days, threshold 1
                Force = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);

            // Cert should be unchanged
            var sameCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));
            Assert.Equal(originalCert, sameCert);
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_CreatesBackup()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                Force = true,
                Verbose = false
            };

            cmd.Execute();

            var backups = BackupManager.ListBackups(Path.Combine(tempDir, "server"));
            Assert.Single(backups);
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_PreservesCA()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var originalCaCert = File.ReadAllText(Path.Combine(tempDir, "certs", "ca.crt"));
            var originalCaKey = File.ReadAllText(Path.Combine(tempDir, "private", "ca.key"));

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                Force = true,
                Verbose = false
            };

            cmd.Execute();

            // CA should be unchanged
            Assert.Equal(originalCaCert, File.ReadAllText(Path.Combine(tempDir, "certs", "ca.crt")));
            Assert.Equal(originalCaKey, File.ReadAllText(Path.Combine(tempDir, "private", "ca.key")));
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_FailsWhenCaMissing()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-renew-test-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                Force = true
            };

            var exitCode = cmd.Execute();

            Assert.Equal(1, exitCode);
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_FailsWhenDirectoryNotFound()
    {
        var cmd = new RenewCommand
        {
            RootDir = Path.Combine(Path.GetTempPath(), $"nonexistent-{Guid.NewGuid():N}"),
            Force = true
        };

        var exitCode = cmd.Execute();

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public void Renew_WithServiceRestart_CallsServiceController()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockService = Substitute.For<IServiceController>();
            mockService.ServiceExists("TestService").Returns(true);
            mockService.RestartService("TestService").Returns(true);

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                Force = true,
                RestartServiceName = "TestService",
                ServiceController = mockService,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            mockService.Received(1).ServiceExists("TestService");
            mockService.Received(1).RestartService("TestService");
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_WithNonexistentService_SkipsRestart()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockService = Substitute.For<IServiceController>();
            mockService.ServiceExists("NoSuchService").Returns(false);

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                Force = true,
                RestartServiceName = "NoSuchService",
                ServiceController = mockService,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            mockService.DidNotReceive().RestartService(Arg.Any<string>());
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_MultipleRenewals_PrunesBackups()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            // Do 7 renewals to trigger pruning (keep 5).
            // The random suffix in backup directory names guarantees uniqueness
            // even without any delay between renewals.
            for (int i = 0; i < 7; i++)
            {
                var cmd = new RenewCommand
                {
                    RootDir = tempDir,
                    ServerValidDays = 30,
                    Force = true,
                    Verbose = false
                };
                var exitCode = cmd.Execute();
                Assert.Equal(0, exitCode);
            }

            var backups = BackupManager.ListBackups(Path.Combine(tempDir, "server"));
            Assert.Equal(5, backups.Count);
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_WithHighThreshold_RenewsEvenWithTimeRemaining()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var originalCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));

            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                RenewThresholdDays = 9999, // Very high threshold
                Force = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);

            // Should have renewed because 30-day cert is within 9999-day threshold
            var newCert = File.ReadAllText(Path.Combine(tempDir, "server", "localhost.crt"));
            Assert.NotEqual(originalCert, newCert);
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Renew_CreatesLogFile()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var cmd = new RenewCommand
            {
                RootDir = tempDir,
                ServerValidDays = 30,
                Force = true,
                Verbose = false
            };

            cmd.Execute();

            Assert.True(File.Exists(Path.Combine(tempDir, "renew-cert.log")));
        }
        finally
        {
            Cleanup(tempDir);
        }
    }
}
