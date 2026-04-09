using LocalCA.Core;

namespace LocalCA.Cli.Tests;

public class BundleCommandTests
{
    [Fact]
    public void Bundle_WithValidSource_ProducesCompleteBundle()
    {
        var sourceDir = Path.Combine(Path.GetTempPath(), $"localca-cli-bundle-src-{Guid.NewGuid():N}");
        var outputDir = Path.Combine(Path.GetTempPath(), $"localca-cli-bundle-out-{Guid.NewGuid():N}");
        try
        {
            // Create fake publish output
            Directory.CreateDirectory(sourceDir);
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Cli.dll"), "cli-dll");
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Core.dll"), "core-dll");

            var cmd = new BundleCommand
            {
                OutputDir = outputDir,
                SourceDir = sourceDir,
                IncludeScripts = false,
                Verbose = true
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            Assert.True(File.Exists(Path.Combine(outputDir, "MANIFEST.json")));
            Assert.True(File.Exists(Path.Combine(outputDir, "BUNDLE-README.txt")));
            Assert.True(File.Exists(Path.Combine(outputDir, "cli", "LocalCA.Cli.dll")));
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
    public void Bundle_WithRuntimeIdentifier_IncludesInManifest()
    {
        var sourceDir = Path.Combine(Path.GetTempPath(), $"localca-cli-bundle-rid-{Guid.NewGuid():N}");
        var outputDir = Path.Combine(Path.GetTempPath(), $"localca-cli-bundle-ridout-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(sourceDir);
            File.WriteAllText(Path.Combine(sourceDir, "LocalCA.Cli.dll"), "dll");

            var cmd = new BundleCommand
            {
                OutputDir = outputDir,
                SourceDir = sourceDir,
                RuntimeIdentifier = "linux-x64",
                IncludeScripts = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();

            Assert.Equal(0, exitCode);
            var manifest = File.ReadAllText(Path.Combine(outputDir, "MANIFEST.json"));
            Assert.Contains("linux-x64", manifest);
        }
        finally
        {
            if (Directory.Exists(sourceDir))
                Directory.Delete(sourceDir, recursive: true);
            if (Directory.Exists(outputDir))
                Directory.Delete(outputDir, recursive: true);
        }
    }
}
