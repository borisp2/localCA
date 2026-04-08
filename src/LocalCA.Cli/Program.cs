using System.CommandLine;
using LocalCA.Core;

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
    verboseOption
};

installCommand.SetHandler((rootDir, appName, caValidDays, serverValidDays, force, verbose) =>
{
    var cmd = new InstallCommand
    {
        RootDir = rootDir,
        AppName = appName,
        CaValidDays = caValidDays,
        ServerValidDays = serverValidDays,
        Force = force,
        Verbose = verbose
    };
    Environment.ExitCode = cmd.Execute();
}, rootDirOption, appNameOption, caValidDaysOption, serverValidDaysOption, forceOption, verboseOption);

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

// ── root command ────────────────────────────────────────────────

var rootCommand = new RootCommand("LocalCA — localhost certificate authority toolkit (C# implementation)")
{
    installCommand,
    verifyCommand,
    statusCommand
};

return await rootCommand.InvokeAsync(args);
