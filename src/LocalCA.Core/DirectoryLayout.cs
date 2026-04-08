namespace LocalCA.Core;

/// <summary>
/// Creates and validates the LocalCA directory layout.
/// </summary>
public static class DirectoryLayout
{
    public static readonly string[] RequiredSubdirectories =
    {
        "private",
        "certs",
        "server"
    };

    /// <summary>
    /// Creates the full directory tree under rootDir.
    /// Returns the list of created directories.
    /// </summary>
    public static IReadOnlyList<string> EnsureDirectories(string rootDir)
    {
        var created = new List<string>();

        if (!Directory.Exists(rootDir))
        {
            Directory.CreateDirectory(rootDir);
            created.Add(rootDir);
        }

        foreach (var sub in RequiredSubdirectories)
        {
            var path = Path.Combine(rootDir, sub);
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
                created.Add(path);
            }
        }

        // Create index.txt and serial file (matching PS1 behavior)
        var indexPath = Path.Combine(rootDir, "index.txt");
        if (!File.Exists(indexPath))
            File.WriteAllText(indexPath, "");

        var serialPath = Path.Combine(rootDir, "serial");
        if (!File.Exists(serialPath))
            File.WriteAllText(serialPath, "01");

        return created;
    }

    /// <summary>
    /// Returns true if the directory layout already contains CA artifacts.
    /// </summary>
    public static bool HasExistingCa(string rootDir)
    {
        return File.Exists(Path.Combine(rootDir, "private", "ca.key"))
            && File.Exists(Path.Combine(rootDir, "certs", "ca.crt"));
    }
}
