namespace LocalCA.Core.Tests;

public class DirectoryLayoutTests
{
    [Fact]
    public void EnsureDirectories_CreatesExpectedStructure()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-test-{Guid.NewGuid():N}");
        try
        {
            DirectoryLayout.EnsureDirectories(tempDir);

            Assert.True(Directory.Exists(Path.Combine(tempDir, "private")));
            Assert.True(Directory.Exists(Path.Combine(tempDir, "certs")));
            Assert.True(Directory.Exists(Path.Combine(tempDir, "server")));
            Assert.True(File.Exists(Path.Combine(tempDir, "index.txt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "serial")));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void HasExistingCa_ReturnsFalse_WhenEmpty()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-test-{Guid.NewGuid():N}");
        try
        {
            DirectoryLayout.EnsureDirectories(tempDir);
            Assert.False(DirectoryLayout.HasExistingCa(tempDir));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }
}
