using LocalCA.Core;

namespace LocalCA.Core.Tests;

public class ConfigLoaderTests
{
    [Fact]
    public void FindConfigFile_ReturnsNull_WhenNoFileExists()
    {
        var result = ConfigLoader.FindConfigFile(null, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));
        Assert.Null(result);
    }

    [Fact]
    public void FindConfigFile_ReturnsExplicitPath_WhenFileExists()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "{}");
            var result = ConfigLoader.FindConfigFile(tempFile);
            Assert.Equal(Path.GetFullPath(tempFile), result);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void FindConfigFile_ReturnsNull_WhenExplicitPathDoesNotExist()
    {
        var result = ConfigLoader.FindConfigFile("/nonexistent/path/localca.json");
        Assert.Null(result);
    }

    [Fact]
    public void FindConfigFile_FindsFileInRootDir()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"localca-cfg-test-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);
            var configPath = Path.Combine(tempDir, "localca.json");
            File.WriteAllText(configPath, "{}");

            var result = ConfigLoader.FindConfigFile(null, tempDir);
            Assert.Equal(Path.GetFullPath(configPath), result);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void Load_ReturnsEmptyConfig_WhenFileDoesNotExist()
    {
        var config = ConfigLoader.Load("/nonexistent/localca.json");
        Assert.Null(config.RootDir);
        Assert.Null(config.AppName);
        Assert.Null(config.CaValidDays);
    }

    [Fact]
    public void Load_ParsesAllFields()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, """
            {
                "rootDir": "/tmp/TestCA",
                "appName": "TestApp",
                "caValidDays": 365,
                "serverValidDays": 90,
                "thresholdDays": 14,
                "httpsPort": 8443,
                "verbose": true,
                "restartService": "MyService"
            }
            """);

            var config = ConfigLoader.Load(tempFile);

            Assert.Equal("/tmp/TestCA", config.RootDir);
            Assert.Equal("TestApp", config.AppName);
            Assert.Equal(365, config.CaValidDays);
            Assert.Equal(90, config.ServerValidDays);
            Assert.Equal(14, config.ThresholdDays);
            Assert.Equal(8443, config.HttpsPort);
            Assert.True(config.Verbose);
            Assert.Equal("MyService", config.RestartService);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void Load_SupportsCommentsAndTrailingCommas()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, """
            {
                // This is a comment
                "appName": "CommentApp",
                "verbose": true,
            }
            """);

            var config = ConfigLoader.Load(tempFile);
            Assert.Equal("CommentApp", config.AppName);
            Assert.True(config.Verbose);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void Load_IsCaseInsensitive()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, """
            {
                "RootDir": "/tmp/CaseTest",
                "APPNAME": "CaseApp"
            }
            """);

            var config = ConfigLoader.Load(tempFile);
            Assert.Equal("/tmp/CaseTest", config.RootDir);
            // APPNAME won't match because JSON deserialization is case-insensitive
            // but the property mapping is by JsonPropertyName attribute ("appName")
            // "APPNAME" matches "appName" case-insensitively
            Assert.Equal("CaseApp", config.AppName);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ResolveString_CliTakesPrecedence()
    {
        var result = ConfigLoader.ResolveString("cli-value", null, "config-value", "default");
        Assert.Equal("cli-value", result);
    }

    [Fact]
    public void ResolveString_ConfigUsedWhenCliNull()
    {
        var result = ConfigLoader.ResolveString(null, null, "config-value", "default");
        Assert.Equal("config-value", result);
    }

    [Fact]
    public void ResolveString_DefaultUsedWhenAllNull()
    {
        var result = ConfigLoader.ResolveString(null, null, null, "default");
        Assert.Equal("default", result);
    }

    [Fact]
    public void ResolveInt_CliTakesPrecedence()
    {
        var result = ConfigLoader.ResolveInt(100, 365, null, 200, 365);
        Assert.Equal(100, result);
    }

    [Fact]
    public void ResolveInt_ConfigUsedWhenCliIsDefault()
    {
        var result = ConfigLoader.ResolveInt(365, 365, null, 200, 365);
        Assert.Equal(200, result);
    }

    [Fact]
    public void ResolveInt_DefaultUsedWhenAllNull()
    {
        var result = ConfigLoader.ResolveInt(365, 365, null, null, 365);
        Assert.Equal(365, result);
    }

    [Fact]
    public void ResolveBool_CliTrueTakesPrecedence()
    {
        var result = ConfigLoader.ResolveBool(true, null, false, false);
        Assert.True(result);
    }

    [Fact]
    public void ResolveBool_ConfigUsedWhenCliFalse()
    {
        var result = ConfigLoader.ResolveBool(false, null, true, false);
        Assert.True(result);
    }

    [Fact]
    public void ResolveBool_DefaultUsedWhenAllFalseOrNull()
    {
        var result = ConfigLoader.ResolveBool(false, null, null, false);
        Assert.False(result);
    }
}
