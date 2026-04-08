using LocalCA.Core;

namespace LocalCA.Cli.Tests;

public class ConfigLoaderIntegrationTests
{
    [Fact]
    public void Install_WithConfigFile_UsesConfigValues()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cfg-integ-{Guid.NewGuid():N}");
        try
        {
            // Create a config file that sets the app name
            Directory.CreateDirectory(tempDir);
            var configPath = Path.Combine(tempDir, "localca.json");
            File.WriteAllText(configPath, """
            {
                "appName": "ConfigTestApp",
                "caValidDays": 100,
                "serverValidDays": 30,
                "verbose": false
            }
            """);

            // Load config and verify values
            var config = ConfigLoader.Load(configPath);
            Assert.Equal("ConfigTestApp", config.AppName);
            Assert.Equal(100, config.CaValidDays);
            Assert.Equal(30, config.ServerValidDays);
            Assert.False(config.Verbose);

            // Use config to create an install command
            var cmd = new InstallCommand
            {
                RootDir = tempDir,
                AppName = config.AppName ?? "MyApp",
                CaValidDays = config.CaValidDays ?? 3650,
                ServerValidDays = config.ServerValidDays ?? 825,
                Force = false,
                Verbose = false
            };

            var exitCode = cmd.Execute();
            Assert.Equal(0, exitCode);

            // Verify cert was created
            Assert.True(File.Exists(Path.Combine(tempDir, "certs", "ca.crt")));
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void ConfigLoader_PrecedenceWorks_CliOverridesConfig()
    {
        // CLI value (non-null) should override config
        var result = ConfigLoader.ResolveString("from-cli", null, "from-config", "default");
        Assert.Equal("from-cli", result);

        // Config should be used when CLI is null
        var result2 = ConfigLoader.ResolveString(null, null, "from-config", "default");
        Assert.Equal("from-config", result2);

        // Default when both null
        var result3 = ConfigLoader.ResolveString(null, null, null, "default");
        Assert.Equal("default", result3);
    }
}
