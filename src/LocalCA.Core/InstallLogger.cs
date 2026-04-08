namespace LocalCA.Core;

/// <summary>
/// Simple timestamped logger that writes to a file and optionally to the console.
/// </summary>
public sealed class InstallLogger : IDisposable
{
    private readonly StreamWriter? _fileWriter;
    private readonly bool _verbose;

    public InstallLogger(string? logFilePath = null, bool verbose = false)
    {
        _verbose = verbose;

        if (logFilePath != null)
        {
            var dir = Path.GetDirectoryName(logFilePath);
            if (dir != null && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            _fileWriter = new StreamWriter(logFilePath, append: true) { AutoFlush = true };
        }
    }

    public void Info(string message) => Log("INFO", message);
    public void Warn(string message) => Log("WARN", message);
    public void Error(string message) => Log("ERROR", message);
    public void Phase(int number, string description) =>
        Log("PHASE", $"[{number}] {description}");

    private void Log(string level, string message)
    {
        var line = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}";

        _fileWriter?.WriteLine(line);

        if (_verbose || level is "ERROR" or "WARN" or "PHASE")
            Console.WriteLine(line);
    }

    public void Dispose()
    {
        _fileWriter?.Dispose();
    }
}
