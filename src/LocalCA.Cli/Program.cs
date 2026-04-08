using System.CommandLine;
using LocalCA.Core;

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

var rootCommand = new RootCommand("LocalCA — localhost certificate authority toolkit (C# implementation)")
{
    installCommand
};

return await rootCommand.InvokeAsync(args);
