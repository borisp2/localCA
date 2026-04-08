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
        var (stopExit, _) = _processRunner.Run("sc", $"stop \"{serviceName}\"");

        // Wait briefly for the service to stop
        // sc stop is async; query until stopped or timeout
        for (int i = 0; i < 10; i++)
        {
            var (_, output) = _processRunner.Run("sc", $"query \"{serviceName}\"");
            if (output.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
                break;

            Thread.Sleep(500);
        }

        var (startExit, _) = _processRunner.Run("sc", $"start \"{serviceName}\"");
        return startExit == 0;
    }

    public bool ServiceExists(string serviceName)
    {
        var (exitCode, _) = _processRunner.Run("sc", $"query \"{serviceName}\"");
        return exitCode == 0;
    }
}
