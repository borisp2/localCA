using LocalCA.Core;
using NSubstitute;

namespace LocalCA.Cli.Tests;

public class UninstallCommandTests
{
    private string SetupInstalledCA()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-uninstall-test-{Guid.NewGuid():N}");
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
    public void Uninstall_WithRemoveFiles_DeletesAllArtifacts()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                RemoveFiles = true,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            Assert.False(Directory.Exists(tempDir));
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_WithoutRemoveFiles_KeepsDirectory()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                RemoveFiles = false,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            Assert.True(Directory.Exists(tempDir));
            Assert.True(File.Exists(Path.Combine(tempDir, "certs", "ca.crt")));
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_RemovesTrustStoreEntryByThumbprint()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            cmd.Execute();

            // Should have attempted thumbprint-based removal
            mockTrust.Received(1).RemoveCaCertificate(Arg.Any<string>());
            // Should also attempt subject-based removal
            mockTrust.Received(1).RemoveBySubject("TestApp Localhost Root CA");
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_FallsBackToSubjectRemoval_WhenCaCertMissing()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-uninstall-test-{Guid.NewGuid():N}");
        try
        {
            // Create directory but no CA cert
            Directory.CreateDirectory(Path.Combine(tempDir, "certs"));

            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(1);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            // Should NOT have called RemoveCaCertificate (no thumbprint available)
            mockTrust.DidNotReceive().RemoveCaCertificate(Arg.Any<string>());
            // Should have called RemoveBySubject
            mockTrust.Received(1).RemoveBySubject("TestApp Localhost Root CA");
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_RemovesFirewallRule()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists("TestApp HTTPS (localhost:443)").Returns(true);
            mockFirewall.RemoveInboundRule("TestApp HTTPS (localhost:443)").Returns(true);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                HttpsPort = 443,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            cmd.Execute();

            mockFirewall.Received(1).RemoveInboundRule("TestApp HTTPS (localhost:443)");
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_SkipsFirewallRemoval_WhenRuleNotFound()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            cmd.Execute();

            mockFirewall.DidNotReceive().RemoveInboundRule(Arg.Any<string>());
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_CustomPort_MatchesCorrectRuleName()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists("TestApp HTTPS (localhost:5001)").Returns(true);
            mockFirewall.RemoveInboundRule("TestApp HTTPS (localhost:5001)").Returns(true);

            var cmd = new UninstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                HttpsPort = 5001,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };

            cmd.Execute();

            mockFirewall.Received(1).RemoveInboundRule("TestApp HTTPS (localhost:5001)");
        }
        finally
        {
            Cleanup(tempDir);
        }
    }

    [Fact]
    public void Uninstall_IsIdempotent_RunsTwiceWithoutError()
    {
        var tempDir = SetupInstalledCA();
        try
        {
            var mockTrust = Substitute.For<ITrustStore>();
            mockTrust.RemoveCaCertificate(Arg.Any<string>()).Returns(true);
            mockTrust.RemoveBySubject(Arg.Any<string>()).Returns(0);

            var mockFirewall = Substitute.For<IFirewallManager>();
            mockFirewall.RuleExists(Arg.Any<string>()).Returns(false);

            // First uninstall with file removal
            var cmd1 = new UninstallCommand
            {
                RootDir = tempDir,
                RemoveFiles = true,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };
            Assert.Equal(0, cmd1.Execute());

            // Second uninstall on already-removed directory
            var cmd2 = new UninstallCommand
            {
                RootDir = tempDir,
                RemoveFiles = true,
                YesConfirm = true,
                TrustStore = mockTrust,
                FirewallManager = mockFirewall
            };
            Assert.Equal(0, cmd2.Execute());
        }
        finally
        {
            Cleanup(tempDir);
        }
    }
}
