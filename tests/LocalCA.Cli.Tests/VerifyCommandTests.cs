using LocalCA.Core;

namespace LocalCA.Cli.Tests;

public class VerifyCommandTests
{
    [Fact]
    public void Verify_AfterInstall_ReturnsZero()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-verify-{Guid.NewGuid():N}");
        try
        {
            var install = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "VerifyCliTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, install.Execute());

            var verify = new VerifyCommand
            {
                RootDir = tempDir,
                Verbose = true
            };
            Assert.Equal(0, verify.Execute());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Verify_WithoutArtifacts_ReturnsOne()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-verify-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var verify = new VerifyCommand
            {
                RootDir = tempDir,
                Verbose = false
            };
            Assert.Equal(1, verify.Execute());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
