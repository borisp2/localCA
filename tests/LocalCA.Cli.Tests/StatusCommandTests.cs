using LocalCA.Core;

namespace LocalCA.Cli.Tests;

public class StatusCommandTests
{
    [Fact]
    public void Status_AfterInstall_ReturnsZero()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-status-{Guid.NewGuid():N}");
        try
        {
            var install = new InstallCommand
            {
                RootDir = tempDir,
                AppName = "StatusCliTest",
                CaValidDays = 365,
                ServerValidDays = 30
            };
            Assert.Equal(0, install.Execute());

            var status = new StatusCommand { RootDir = tempDir };
            Assert.Equal(0, status.Execute());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Status_NonexistentDir_ReturnsOne()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-status-{Guid.NewGuid():N}");
        // Don't create the directory

        var status = new StatusCommand { RootDir = tempDir };
        Assert.Equal(1, status.Execute());
    }

    [Fact]
    public void Status_EmptyDir_ReturnsOne()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cli-status-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);

            var status = new StatusCommand { RootDir = tempDir };
            Assert.Equal(1, status.Execute());
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
