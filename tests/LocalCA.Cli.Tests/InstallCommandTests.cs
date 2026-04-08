using LocalCA.Core;

namespace LocalCA.Cli.Tests;

public class InstallCommandTests
{
    [Fact]
    public void Install_CreatesFullDirectoryLayoutAndArtifacts()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "TestApp",
                CaValidDays = 365,
                ServerValidDays = 30,
                Force = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);

            // Verify directory structure
            Assert.True(Directory.Exists(Path.Combine(tempDir, "private")));
            Assert.True(Directory.Exists(Path.Combine(tempDir, "certs")));
            Assert.True(Directory.Exists(Path.Combine(tempDir, "server")));

            // Verify all artifacts
            Assert.True(File.Exists(Path.Combine(tempDir, "private", "ca.key")));
            Assert.True(File.Exists(Path.Combine(tempDir, "certs", "ca.crt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.key")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.crt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost.pfx")));
            Assert.True(File.Exists(Path.Combine(tempDir, "server", "localhost-fullchain.pem")));
            Assert.True(File.Exists(Path.Combine(tempDir, "install-ca.log")));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Install_WithoutForce_SkipsIfCaExists()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-test-{Guid.NewGuid():N}");
        try
        {
            // First install
            var cmd1 = new InstallCommand { RootDir = tempDir, Force = false };
            Assert.Equal(0, cmd1.Execute());

            // Second install without force should succeed (exits 0 with warning)
            var cmd2 = new InstallCommand { RootDir = tempDir, Force = false };
            Assert.Equal(0, cmd2.Execute());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Install_WithForce_OverwritesExisting()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-test-{Guid.NewGuid():N}");
        try
        {
            var cmd1 = new InstallCommand { RootDir = tempDir, Force = false };
            Assert.Equal(0, cmd1.Execute());

            var originalPfx = File.ReadAllBytes(Path.Combine(tempDir, "server", "localhost.pfx"));

            var cmd2 = new InstallCommand { RootDir = tempDir, Force = true };
            Assert.Equal(0, cmd2.Execute());

            var newPfx = File.ReadAllBytes(Path.Combine(tempDir, "server", "localhost.pfx"));

            // PFX should be different (new key generated)
            Assert.NotEqual(originalPfx, newPfx);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
