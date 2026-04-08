using LocalCA.Core;

namespace LocalCA.Core.Tests;

public class BundleCommandTests
{
    [Fact]
    public void Bundle_FailsGracefully_WhenNoSourceDir()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-test-{Guid.NewGuid():N}");
        try
        {
            var cmd = new BundleCommand
            {
                OutputDir = tempDir,
                SourceDir = Path.Combine(Path.GetTempPath(), "nonexistent-" + Guid.NewGuid().ToString("N")),
                Verbose = false
            };

            var exitCode = cmd.Execute();
            Assert.Equal(1, exitCode);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Bundle_CopiesSourceArtifacts_AndCreatesManifest()
    {
        var sourceDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-src-{Guid.NewGuid():N}");
        var outputDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-out-{Guid.NewGuid():N}");
        try
        {
            // Create fake published artifacts
            Directory.CreateDirectory(sourceDir);
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Cli.dll"), "fake-dll");
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Core.dll"), "fake-core-dll");
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Cli.runtimeconfig.json"), "{}");

            var cmd = new BundleCommand
            {
                OutputDir = outputDir,
                SourceDir = sourceDir,
                IncludeScripts = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);

            // Verify cli subdirectory was created with artifacts
            Assert.True(Directory.Exists(Path.Combine(outputDir, "cli")));
            Assert.True(File.Exists(Path.Combine(outputDir, "cli", "LocalCA.Cli.dll")));
            Assert.True(File.Exists(Path.Combine(outputDir, "cli", "LocalCA.Core.dll")));
            Assert.True(File.Exists(Path.Combine(outputDir, "cli", "LocalCA.Cli.runtimeconfig.json")));

            // Verify manifest
            Assert.True(File.Exists(Path.Combine(outputDir, "MANIFEST.json")));
            var manifestJson = File.ReadAllText(Path.Combine(outputDir, "MANIFEST.json"));
            Assert.Contains("LocalCA", manifestJson);
            Assert.Contains("LocalCA.Cli.dll", manifestJson);

            // Verify readme
            Assert.True(File.Exists(Path.Combine(outputDir, "BUNDLE-README.txt")));

            // Verify log
            Assert.True(File.Exists(Path.Combine(outputDir, "bundle.log")));
        }
        finally
        {
            if (Directory.Exists(sourceDir))
                Directory.Delete(sourceDir, recursive: true);
            if (Directory.Exists(outputDir))
                Directory.Delete(outputDir, recursive: true);
        }
    }

    [Fact]
    public void Bundle_FailsGracefully_WhenSourceDirEmpty()
    {
        var sourceDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-empty-{Guid.NewGuid():N}");
        var outputDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-out-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(sourceDir);
            // Source dir exists but is empty

            var cmd = new BundleCommand
            {
                OutputDir = outputDir,
                SourceDir = sourceDir,
                IncludeScripts = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();
            Assert.Equal(1, exitCode);
        }
        finally
        {
            if (Directory.Exists(sourceDir))
                Directory.Delete(sourceDir, recursive: true);
            if (Directory.Exists(outputDir))
                Directory.Delete(outputDir, recursive: true);
        }
    }

    [Fact]
    public void Bundle_CreatesOutputDir_WhenNotExists()
    {
        var sourceDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-src-{Guid.NewGuid():N}");
        var outputDir = Path.Combine(Path.GetTempPath(), $"localca-bundle-new-{Guid.NewGuid():N}", "nested");
        try
        {
            Directory.CreateDirectory(sourceDir);
            File.WriteAllText(Path.Combine(sourceDir, "test.dll"), "content");

            var cmd = new BundleCommand
            {
                OutputDir = outputDir,
                SourceDir = sourceDir,
                IncludeScripts = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();
            Assert.Equal(0, exitCode);
            Assert.True(Directory.Exists(outputDir));
        }
        finally
        {
            if (Directory.Exists(sourceDir))
                Directory.Delete(sourceDir, recursive: true);
            var parentDir = Path.GetDirectoryName(outputDir);
            if (parentDir != null && Directory.Exists(parentDir))
                Directory.Delete(parentDir, recursive: true);
        }
    }
}
