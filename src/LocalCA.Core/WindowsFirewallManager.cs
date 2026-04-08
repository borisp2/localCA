using System.Diagnostics;

namespace LocalCA.Core;

/// <summary>
/// Windows Firewall rule management via netsh advfirewall.
/// Wraps shell execution behind the IFirewallManager interface for testability.
/// </summary>
public sealed class WindowsFirewallManager : IFirewallManager
{
    private readonly IProcessRunner _processRunner;

    public WindowsFirewallManager()
        : this(new SystemProcessRunner())
    {
    }

    public WindowsFirewallManager(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public bool AddInboundRule(string ruleName, int port)
    {
        var (exitCode, _) = _processRunner.Run(
            "netsh",
            $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow protocol=TCP localport={port}");

        return exitCode == 0;
    }

    public bool RemoveInboundRule(string ruleName)
    {
        var (exitCode, _) = _processRunner.Run(
            "netsh",
            $"advfirewall firewall delete rule name=\"{ruleName}\"");

        return exitCode == 0;
    }

    public bool RuleExists(string ruleName)
    {
        var (exitCode, _) = _processRunner.Run(
            "netsh",
            $"advfirewall firewall show rule name=\"{ruleName}\"");

        return exitCode == 0;
    }
}

/// <summary>
/// Abstraction for running external processes. Enables unit testing of
/// components that shell out to system utilities.
/// </summary>
public interface IProcessRunner
{
    (int ExitCode, string Output) Run(string fileName, string arguments);
}

/// <summary>
/// Default process runner that executes real system processes.
/// </summary>
public sealed class SystemProcessRunner : IProcessRunner
{
    public (int ExitCode, string Output) Run(string fileName, string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, output);
    }
}
