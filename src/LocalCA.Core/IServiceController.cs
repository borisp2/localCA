namespace LocalCA.Core;

/// <summary>
/// Abstraction for Windows service restart operations.
/// Enables unit testing without requiring actual service control.
/// </summary>
public interface IServiceController
{
    /// <summary>
    /// Restart a Windows service by name.
    /// Returns true if the service was restarted successfully.
    /// </summary>
    bool RestartService(string serviceName);

    /// <summary>
    /// Check whether a service with the given name exists.
    /// </summary>
    bool ServiceExists(string serviceName);
}

/// <summary>
/// Service controller that shells out to sc.exe / net stop+start
/// for cross-platform testability via IProcessRunner.
/// </summary>
public sealed class WindowsServiceController : IServiceController
{
    private readonly IProcessRunner _processRunner;

    public WindowsServiceController()
        : this(new SystemProcessRunner())
    {
    }

    public WindowsServiceController(IProcessRunner processRunner)
    {
        _processRunner = processRunner;
    }

    public bool RestartService(string serviceName)
    {
        var (stopExit, stopOutput) = _processRunner.Run("sc", $"stop \"{serviceName}\"");

        // Exit code 0 = stop pending, 1062 = already stopped — both are acceptable.
        // Any other non-zero exit code is a real failure.
        const int AlreadyStopped = 1062;
        if (stopExit != 0 && stopExit != AlreadyStopped)
            return false;

        // sc stop is async; poll until STOPPED or timeout
        bool stopped = stopExit == AlreadyStopped;
        if (!stopped)
        {
            for (int i = 0; i < 10; i++)
            {
                var (_, output) = _processRunner.Run("sc", $"query \"{serviceName}\"");
                if (output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
                {
                    stopped = true;
                    break;
                }

                Thread.Sleep(500);
            }
        }

        // Do not attempt start if the service never reached STOPPED
        if (!stopped)
            return false;

        var (startExit, _) = _processRunner.Run("sc", $"start \"{serviceName}\"");
        return startExit == 0;
    }

    public bool ServiceExists(string serviceName)
    {
        var (exitCode, _) = _processRunner.Run("sc", $"query \"{serviceName}\"");
        return exitCode == 0;
    }
}
