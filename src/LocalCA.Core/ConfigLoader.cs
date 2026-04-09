using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalCA.Core;

/// <summary>
/// Loads optional configuration from a localca.json file.
/// Precedence: CLI args > environment variables > config file > defaults.
/// </summary>
public static class ConfigLoader
{
    public const string DefaultFileName = "localca.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Searches for a config file in the following order:
    /// 1. Explicit path (if provided)
    /// 2. Current working directory
    /// 3. Root directory (if provided)
    /// Returns null if no config file is found.
    /// </summary>
    public static string? FindConfigFile(string? explicitPath = null, string? rootDir = null)
    {
        if (explicitPath != null)
        {
            return File.Exists(explicitPath) ? Path.GetFullPath(explicitPath) : null;
        }

        var cwdPath = Path.Combine(Directory.GetCurrentDirectory(), DefaultFileName);
        if (File.Exists(cwdPath))
            return Path.GetFullPath(cwdPath);

        if (rootDir != null)
        {
            var rootPath = Path.Combine(rootDir, DefaultFileName);
            if (File.Exists(rootPath))
                return Path.GetFullPath(rootPath);
        }

        return null;
    }

    /// <summary>
    /// Loads configuration from a JSON file. Returns an empty config if the file doesn't exist.
    /// </summary>
    public static LocalCaConfig Load(string filePath)
    {
        if (!File.Exists(filePath))
            return new LocalCaConfig();

        var json = File.ReadAllText(filePath);
        return JsonSerializer.Deserialize<LocalCaConfig>(json, JsonOptions)
            ?? new LocalCaConfig();
    }

    /// <summary>
    /// Resolves a configuration value using precedence:
    /// CLI arg (non-default) > environment variable > config file value > default.
    /// </summary>
    public static string ResolveString(string? cliValue, string? envVarName, string? configValue, string defaultValue)
    {
        // CLI arg takes precedence (if not null/empty)
        if (!string.IsNullOrEmpty(cliValue))
            return cliValue;

        // Environment variable
        if (envVarName != null)
        {
            var envValue = Environment.GetEnvironmentVariable(envVarName);
            if (!string.IsNullOrEmpty(envValue))
                return envValue;
        }

        // Config file
        if (!string.IsNullOrEmpty(configValue))
            return configValue;

        return defaultValue;
    }

    /// <summary>
    /// Resolves an integer configuration value using precedence.
    /// </summary>
    public static int ResolveInt(int cliValue, int cliDefault, string? envVarName, int? configValue, int defaultValue)
    {
        // CLI arg takes precedence (if different from default)
        if (cliValue != cliDefault)
            return cliValue;

        // Environment variable
        if (envVarName != null)
        {
            var envValue = Environment.GetEnvironmentVariable(envVarName);
            if (!string.IsNullOrEmpty(envValue) && int.TryParse(envValue, out var parsed))
                return parsed;
        }

        // Config file
        if (configValue.HasValue)
            return configValue.Value;

        return defaultValue;
    }

    /// <summary>
    /// Resolves a boolean configuration value using precedence.
    /// </summary>
    public static bool ResolveBool(bool cliValue, string? envVarName, bool? configValue, bool defaultValue)
    {
        // CLI arg: true overrides everything
        if (cliValue)
            return true;

        // Environment variable
        if (envVarName != null)
        {
            var envValue = Environment.GetEnvironmentVariable(envVarName);
            if (!string.IsNullOrEmpty(envValue) && bool.TryParse(envValue, out var parsed))
                return parsed;
        }

        // Config file
        if (configValue.HasValue)
            return configValue.Value;

        return defaultValue;
    }
}

/// <summary>
/// Represents the localca.json configuration file structure.
/// All properties are optional — missing values use CLI defaults.
/// </summary>
public sealed class LocalCaConfig
{
    [JsonPropertyName("rootDir")]
    public string? RootDir { get; set; }

    [JsonPropertyName("appName")]
    public string? AppName { get; set; }

    [JsonPropertyName("caValidDays")]
    public int? CaValidDays { get; set; }

    [JsonPropertyName("serverValidDays")]
    public int? ServerValidDays { get; set; }

    [JsonPropertyName("thresholdDays")]
    public int? ThresholdDays { get; set; }

    [JsonPropertyName("httpsPort")]
    public int? HttpsPort { get; set; }

    [JsonPropertyName("verbose")]
    public bool? Verbose { get; set; }

    [JsonPropertyName("restartService")]
    public string? RestartService { get; set; }
}
