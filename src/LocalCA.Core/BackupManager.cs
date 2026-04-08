namespace LocalCA.Core;

/// <summary>
/// Manages timestamped backups of server certificate artifacts
/// and prunes old backups beyond a configurable retention count.
/// </summary>
public static class BackupManager
{
    /// <summary>
    /// Back up all files (non-directory) in the server directory to a
    /// timestamped subdirectory (backup-yyyyMMdd-HHmmss).
    /// Returns the path to the created backup directory.
    /// </summary>
    public static string BackupServerArtifacts(string serverDir)
    {
        return BackupServerArtifacts(serverDir, DateTime.UtcNow);
    }

    /// <summary>
    /// Back up all files (non-directory) in the server directory to a
    /// timestamped subdirectory using the specified timestamp.
    /// Returns the path to the created backup directory.
    /// </summary>
    public static string BackupServerArtifacts(string serverDir, DateTime timestamp)
    {
        var tag = timestamp.ToString("yyyyMMdd-HHmmss");
        var backupDir = Path.Combine(serverDir, $"backup-{tag}");
        Directory.CreateDirectory(backupDir);

        foreach (var file in Directory.GetFiles(serverDir))
        {
            var fileName = Path.GetFileName(file);
            File.Copy(file, Path.Combine(backupDir, fileName), overwrite: true);
        }

        return backupDir;
    }

    /// <summary>
    /// Remove old backup directories, keeping only the most recent <paramref name="keepCount"/>.
    /// Returns the list of pruned directory paths.
    /// </summary>
    public static IReadOnlyList<string> PruneBackups(string serverDir, int keepCount = 5)
    {
        var pruned = new List<string>();

        var backupDirs = Directory.GetDirectories(serverDir, "backup-*")
            .OrderByDescending(d => Path.GetFileName(d))
            .ToList();

        if (backupDirs.Count <= keepCount)
            return pruned;

        foreach (var dir in backupDirs.Skip(keepCount))
        {
            Directory.Delete(dir, recursive: true);
            pruned.Add(dir);
        }

        return pruned;
    }

    /// <summary>
    /// List all backup directories in the server directory, sorted newest first.
    /// </summary>
    public static IReadOnlyList<string> ListBackups(string serverDir)
    {
        if (!Directory.Exists(serverDir))
            return Array.Empty<string>();

        return Directory.GetDirectories(serverDir, "backup-*")
            .OrderByDescending(d => Path.GetFileName(d))
            .ToList();
    }
}
