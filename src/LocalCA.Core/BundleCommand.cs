using System.Reflection;
using System.Text.Json;

namespace LocalCA.Core;

/// <summary>
/// Packages the LocalCA CLI artifacts, supporting scripts, and docs
/// into a self-contained output directory for distribution.
/// </summary>
public sealed class BundleCommand
{
    public string OutputDir { get; init; } = Path.Combine(Directory.GetCurrentDirectory(), "localca-bundle");
    public string? SourceDir { get; init; }
    public string RuntimeIdentifier { get; init; } = "";
    public bool IncludeScripts { get; init; } = true;
    public bool Verbose { get; init; }

    public int Execute()
    {
        var logPath = Path.Combine(OutputDir, "bundle.log");

        if (!Directory.Exists(OutputDir))
            Directory.CreateDirectory(OutputDir);

        using var log = new InstallLogger(logPath, Verbose);

        try
        {
            return ExecuteCore(log);
        }
        catch (Exception ex)
        {
            log.Error($"Unexpected error: {ex}");
            Console.Error.WriteLine($"Fatal: {ex.Message}");
            return 99;
        }
    }

    private int ExecuteCore(InstallLogger log)
    {
        log.Phase(0, "Pre-flight checks");

        // Determine the source directory containing CLI artifacts
        var sourceDir = ResolveSourceDir(log);
        if (sourceDir == null)
        {
            log.Error("No source directory specified and could not locate published CLI artifacts.");
            Console.Error.WriteLine("Error: Specify --source-dir pointing to a 'dotnet publish' output directory,");
            Console.Error.WriteLine("       or run 'dotnet publish src/LocalCA.Cli -c Release -o <dir>' first.");
            return 1;
        }

        log.Info($"Source directory: {sourceDir}");
        log.Info($"Output directory: {OutputDir}");

        // Phase 1: Copy CLI artifacts
        log.Phase(1, "Copying CLI artifacts");
        var cliOutDir = Path.Combine(OutputDir, "cli");
        if (!Directory.Exists(cliOutDir))
            Directory.CreateDirectory(cliOutDir);

        var copiedCount = CopyDirectory(sourceDir, cliOutDir, log);
        log.Info($"Copied {copiedCount} file(s) to cli/");

        if (copiedCount == 0)
        {
            log.Error("No files found in source directory. Ensure the CLI has been published.");
            return 1;
        }

        // Phase 2: Copy PowerShell scripts (optional)
        if (IncludeScripts)
        {
            log.Phase(2, "Copying PowerShell scripts");
            CopyScripts(log);
        }

        // Phase 3: Generate manifest
        log.Phase(3, "Generating bundle manifest");
        GenerateManifest(cliOutDir, log);

        // Phase 4: Generate quick-start readme
        log.Phase(4, "Generating bundle readme");
        GenerateReadme(log);

        // Summary
        log.Phase(9, "Summary");
        var fileCount = Directory.GetFiles(OutputDir, "*", SearchOption.AllDirectories).Length;
        var totalSize = GetDirectorySize(OutputDir);
        var summary = $"""
            Bundle created successfully.
              Output:    {OutputDir}
              Files:     {fileCount}
              Size:      {FormatSize(totalSize)}
            """;
        log.Info(summary);
        Console.WriteLine(summary);

        return 0;
    }

    private string? ResolveSourceDir(InstallLogger log)
    {
        // 1. Explicit source directory
        if (!string.IsNullOrEmpty(SourceDir))
        {
            if (Directory.Exists(SourceDir))
                return Path.GetFullPath(SourceDir);

            log.Warn($"Specified source directory not found: {SourceDir}");
            return null;
        }

        // 2. Look for common publish output locations relative to CWD
        var candidates = new[]
        {
            Path.Combine(Directory.GetCurrentDirectory(), "src", "LocalCA.Cli", "bin", "Release", "net8.0", "publish"),
            Path.Combine(Directory.GetCurrentDirectory(), "src", "LocalCA.Cli", "bin", "Release", "net8.0",
                string.IsNullOrEmpty(RuntimeIdentifier) ? "publish" : RuntimeIdentifier, "publish"),
        };

        foreach (var candidate in candidates)
        {
            if (Directory.Exists(candidate) && Directory.GetFiles(candidate).Length > 0)
            {
                log.Info($"Auto-detected publish output: {candidate}");
                return candidate;
            }
        }

        return null;
    }

    private int CopyDirectory(string source, string destination, InstallLogger log)
    {
        var count = 0;

        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(source, file);
            var destPath = Path.Combine(destination, relativePath);
            var destDir = Path.GetDirectoryName(destPath);

            if (destDir != null && !Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);

            File.Copy(file, destPath, overwrite: true);
            log.Info($"  {relativePath}");
            count++;
        }

        return count;
    }

    private void CopyScripts(InstallLogger log)
    {
        var scriptsDir = Path.Combine(OutputDir, "scripts");
        if (!Directory.Exists(scriptsDir))
            Directory.CreateDirectory(scriptsDir);

        var scriptNames = new[]
        {
            "Install-LocalCA-Localhost.ps1",
            "Prepare-OfflineBundle.ps1",
            "Renew-ServerCert.ps1",
            "Uninstall-LocalCA.ps1"
        };

        // Search for scripts relative to CWD (repo root)
        var repoRoot = Directory.GetCurrentDirectory();
        var found = 0;

        foreach (var name in scriptNames)
        {
            var src = Path.Combine(repoRoot, name);
            if (File.Exists(src))
            {
                File.Copy(src, Path.Combine(scriptsDir, name), overwrite: true);
                log.Info($"  Copied {name}");
                found++;
            }
        }

        if (found == 0)
            log.Warn("No PowerShell scripts found in current directory.");
        else
            log.Info($"Copied {found} PowerShell script(s) to scripts/");
    }

    private void GenerateManifest(string cliOutDir, InstallLogger log)
    {
        var cliFiles = Directory.GetFiles(cliOutDir, "*", SearchOption.AllDirectories)
            .Select(f => new
            {
                path = Path.GetRelativePath(OutputDir, f),
                size = new FileInfo(f).Length
            })
            .ToArray();

        var manifest = new
        {
            tool = "LocalCA",
            version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0",
            created = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"),
            runtime = RuntimeIdentifier != "" ? RuntimeIdentifier : "portable (requires .NET 8 runtime)",
            platform = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            files = cliFiles
        };

        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        var manifestPath = Path.Combine(OutputDir, "MANIFEST.json");
        File.WriteAllText(manifestPath, json);
        log.Info($"Manifest written: {manifestPath}");
    }

    private void GenerateReadme(InstallLogger log)
    {
        var readmePath = Path.Combine(OutputDir, "BUNDLE-README.txt");
        var content = $"""
            LocalCA CLI Bundle
            ==================
            Created: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC

            CONTENTS:
              cli/        — Published LocalCA CLI (cross-platform .NET 8)
              scripts/    — PowerShell helper scripts (Windows)
              MANIFEST.json — Bundle metadata

            USAGE (with .NET 8 runtime installed):
              cd cli
              dotnet LocalCA.Cli.dll install --root-dir /path/to/CA --verbose

            USAGE (self-contained publish):
              cd cli
              ./LocalCA.Cli install --root-dir /path/to/CA --verbose

            ALL COMMANDS:
              install    — Generate CA + server certificates
              verify     — Validate server cert against CA
              status     — Report artifact existence and cert metadata
              renew      — Rotate server cert (keeps CA)
              uninstall  — Remove trust entries, firewall rules, files
              bundle     — Package CLI artifacts for distribution

            CONFIG FILE:
              Place a localca.json in the working directory or root-dir to set defaults.
              See README.md for format details.

            For full documentation, see: https://github.com/borisp2/localCA
            """;

        File.WriteAllText(readmePath, content);
        log.Info($"Readme written: {readmePath}");
    }

    private static long GetDirectorySize(string path)
    {
        return Directory.GetFiles(path, "*", SearchOption.AllDirectories)
            .Sum(f => new FileInfo(f).Length);
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }
}
