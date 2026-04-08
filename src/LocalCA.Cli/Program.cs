using System.CommandLine;
using LocalCA.Core;

// ── Global config option ───────────────────────────────────────

var configOption = new Option<string?>(
    "--config",
    description: "Path to localca.json config file (default: auto-detect in CWD or root-dir)");

// ── Config file loading helper ─────────────────────────────────

static LocalCaConfig LoadConfig(string? configPath, string? rootDir)
{
    var resolved = ConfigLoader.FindConfigFile(configPath, rootDir);
    if (resolved != null)
    {
        Console.WriteLine($"Using config: {resolved}");
        return ConfigLoader.Load(resolved);
    }
    return new LocalCaConfig();
}

// ── Shared options ──────────────────────────────────────────────

var rootDirOption = new Option<string>(
    "--root-dir",
    description: "Base directory for CA files",
    getDefaultValue: () => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA"));

var appNameOption = new Option<string>(
    "--app-name",
    getDefaultValue: () => "MyApp",
    description: "Application name used in certificate subjects");

var caValidDaysOption = new Option<int>(
    "--ca-valid-days",
    getDefaultValue: () => 3650,
    description: "Root CA lifetime in days");

var serverValidDaysOption = new Option<int>(
    "--server-valid-days",
    getDefaultValue: () => 825,
    description: "Server certificate lifetime in days");

var forceOption = new Option<bool>(
    "--force",
    getDefaultValue: () => false,
    description: "Overwrite existing CA artifacts");

var verboseOption = new Option<bool>(
    "--verbose",
    getDefaultValue: () => false,
    description: "Enable verbose logging to console");

// ── install command ─────────────────────────────────────────────

var installCommand = new Command("install", "Create directory layout, generate CA and server certificates, export artifacts")
{
    rootDirOption,
    appNameOption,
    caValidDaysOption,
    serverValidDaysOption,
    forceOption,
    verboseOption,
    configOption
};

installCommand.SetHandler((rootDir, appName, caValidDays, serverValidDays, force, verbose, configPath) =>
{
    var cfg = LoadConfig(configPath, rootDir);
    var defaultRootDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LocalCA");
    var cmd = new InstallCommand
    {
        RootDir = ConfigLoader.ResolveString(rootDir == defaultRootDir ? null : rootDir, "LOCALCA_ROOT_DIR", cfg.RootDir, defaultRootDir),
        AppName = ConfigLoader.ResolveString(appName == "MyApp" ? null : appName, "LOCALCA_APP_NAME", cfg.AppName, "MyApp"),
        CaValidDays = ConfigLoader.ResolveInt(caValidDays, 3650, "LOCALCA_CA_VALID_DAYS", cfg.CaValidDays, 3650),
        ServerValidDays = ConfigLoader.ResolveInt(serverValidDays, 825, "LOCALCA_SERVER_VALID_DAYS", cfg.ServerValidDays, 825),
        Force = ConfigLoader.ResolveBool(force, "LOCALCA_FORCE", null, false),
        Verbose = ConfigLoader.ResolveBool(verbose, "LOCALCA_VERBOSE", cfg.Verbose, false)
    };
    Environment.ExitCode = cmd.Execute();
}, rootDirOption, appNameOption, caValidDaysOption, serverValidDaysOption, forceOption, verboseOption, configOption);

// ── verify command ──────────────────────────────────────────────

var verifyRootDirOption = new Option<string>(
    "--root-dir",
    description: "Base directory for CA files",
    getDefaultValue: () => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA"));

var verifyVerboseOption = new Option<bool>(
    "--verbose",
    getDefaultValue: () => false,
    description: "Show detailed check results");

var verifyCommand = new Command("verify", "Validate server certificate against the CA and report chain/validity status")
{
    verifyRootDirOption,
    verifyVerboseOption
};

verifyCommand.SetHandler((rootDir, verbose) =>
{
    var cmd = new VerifyCommand
    {
        RootDir = rootDir,
        Verbose = verbose
    };
    Environment.ExitCode = cmd.Execute();
}, verifyRootDirOption, verifyVerboseOption);

// ── status command ──────────────────────────────────────────────

var statusRootDirOption = new Option<string>(
    "--root-dir",
    description: "Base directory for CA files",
    getDefaultValue: () => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA"));

var statusCommand = new Command("status", "Report whether CA/server artifacts exist and display certificate metadata")
{
    statusRootDirOption
};

statusCommand.SetHandler((rootDir) =>
{
    var cmd = new StatusCommand
    {
        RootDir = rootDir
    };
    Environment.ExitCode = cmd.Execute();
}, statusRootDirOption);

// ── renew command ──────────────────────────────────────────────

var renewRootDirOption = new Option<string>(
    "--root-dir",
    description: "Base directory for CA files",
    getDefaultValue: () => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA"));

var renewAppNameOption = new Option<string>(
    "--app-name",
    getDefaultValue: () => "MyApp",
    description: "Application name used in certificate subjects");

var renewServerValidDaysOption = new Option<int>(
    "--server-valid-days",
    getDefaultValue: () => 825,
    description: "New server certificate lifetime in days");

var renewThresholdOption = new Option<int>(
    "--threshold-days",
    getDefaultValue: () => 30,
    description: "Renew only if cert expires within this many days");

var renewRestartServiceOption = new Option<string?>(
    "--restart-service",
    getDefaultValue: () => null,
    description: "Windows service name to restart after renewal");

var renewForceOption = new Option<bool>(
    "--force",
    getDefaultValue: () => false,
    description: "Renew regardless of current cert expiry");

var renewVerboseOption = new Option<bool>(
    "--verbose",
    getDefaultValue: () => false,
    description: "Enable verbose logging to console");

var renewCommand = new Command("renew", "Renew the server certificate using the existing CA")
{
    renewRootDirOption,
    renewAppNameOption,
    renewServerValidDaysOption,
    renewThresholdOption,
    renewRestartServiceOption,
    renewForceOption,
    renewVerboseOption
};

renewCommand.SetHandler((rootDir, appName, serverValidDays, thresholdDays, restartService, force, verbose) =>
{
    var cmd = new RenewCommand
    {
        RootDir = rootDir,
        AppName = appName,
        ServerValidDays = serverValidDays,
        RenewThresholdDays = thresholdDays,
        RestartServiceName = restartService,
        Force = force,
        Verbose = verbose
    };
    Environment.ExitCode = cmd.Execute();
}, renewRootDirOption, renewAppNameOption, renewServerValidDaysOption, renewThresholdOption,
   renewRestartServiceOption, renewForceOption, renewVerboseOption);

// ── uninstall command ──────────────────────────────────────────

var uninstallRootDirOption = new Option<string>(
    "--root-dir",
    description: "Base directory for CA files",
    getDefaultValue: () => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA"));

var uninstallAppNameOption = new Option<string>(
    "--app-name",
    getDefaultValue: () => "MyApp",
    description: "Application name (for trust store and firewall rule matching)");

var uninstallPortOption = new Option<int>(
    "--https-port",
    getDefaultValue: () => 443,
    description: "HTTPS port (for firewall rule matching)");

var uninstallRemoveFilesOption = new Option<bool>(
    "--remove-files",
    getDefaultValue: () => false,
    description: "Delete all CA files and directories");

var uninstallYesOption = new Option<bool>(
    "--yes",
    getDefaultValue: () => false,
    description: "Skip confirmation prompt");

var uninstallVerboseOption = new Option<bool>(
    "--verbose",
    getDefaultValue: () => false,
    description: "Enable verbose logging to console");

var uninstallCommand = new Command("uninstall", "Remove trust store entries, firewall rules, and optionally all CA files")
{
    uninstallRootDirOption,
    uninstallAppNameOption,
    uninstallPortOption,
    uninstallRemoveFilesOption,
    uninstallYesOption,
    uninstallVerboseOption
};

uninstallCommand.SetHandler((rootDir, appName, httpsPort, removeFiles, yes, verbose) =>
{
    var cmd = new UninstallCommand
    {
        RootDir = rootDir,
        AppName = appName,
        HttpsPort = httpsPort,
        RemoveFiles = removeFiles,
        YesConfirm = yes,
        Verbose = verbose
    };
    Environment.ExitCode = cmd.Execute();
}, uninstallRootDirOption, uninstallAppNameOption, uninstallPortOption,
   uninstallRemoveFilesOption, uninstallYesOption, uninstallVerboseOption);

// ── bundle command ─────────────────────────────────────────────

var bundleOutputOption = new Option<string>(
    "--output-dir",
    getDefaultValue: () => Path.Combine(Directory.GetCurrentDirectory(), "localca-bundle"),
    description: "Output directory for the bundle");

var bundleSourceOption = new Option<string?>(
    "--source-dir",
    getDefaultValue: () => null,
    description: "Published CLI artifacts directory (from 'dotnet publish')");

var bundleRidOption = new Option<string>(
    "--runtime",
    getDefaultValue: () => "",
    description: "Runtime identifier (e.g. win-x64, linux-x64) for manifest metadata");

var bundleNoScriptsOption = new Option<bool>(
    "--no-scripts",
    getDefaultValue: () => false,
    description: "Exclude PowerShell scripts from the bundle");

var bundleVerboseOption = new Option<bool>(
    "--verbose",
    getDefaultValue: () => false,
    description: "Verbose console output");

var bundleCommand = new Command("bundle", "Package CLI artifacts and supporting files into a distributable bundle")
{
    bundleOutputOption,
    bundleSourceOption,
    bundleRidOption,
    bundleNoScriptsOption,
    bundleVerboseOption
};

bundleCommand.SetHandler((outputDir, sourceDir, runtime, noScripts, verbose) =>
{
    var cmd = new BundleCommand
    {
        OutputDir = outputDir,
        SourceDir = sourceDir,
        RuntimeIdentifier = runtime,
        IncludeScripts = !noScripts,
        Verbose = verbose
    };
    Environment.ExitCode = cmd.Execute();
}, bundleOutputOption, bundleSourceOption, bundleRidOption, bundleNoScriptsOption, bundleVerboseOption);

// ── root command ────────────────────────────────────────────────

var rootCommand = new RootCommand("LocalCA — localhost certificate authority toolkit (C# implementation)")
{
    installCommand,
    verifyCommand,
    statusCommand,
    renewCommand,
    uninstallCommand,
    bundleCommand
};

return await rootCommand.InvokeAsync(args);
