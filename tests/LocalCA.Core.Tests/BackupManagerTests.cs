namespace LocalCA.Core.Tests;

public class BackupManagerTests
{
    private string CreateTempServerDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"localca-backup-test-{Guid.NewGuid():N}", "server");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private void CleanupDir(string dir)
    {
        // Go up to parent (the test root that contains "server")
        var parent = Path.GetDirectoryName(dir)!;
        if (Directory.Exists(parent))
            Directory.Delete(parent, recursive: true);
    }

    [Fact]
    public void BackupServerArtifacts_CreatesTimestampedBackupDirectory()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            File.WriteAllText(Path.Combine(serverDir, "localhost.crt"), "cert-data");
            File.WriteAllText(Path.Combine(serverDir, "localhost.key"), "key-data");

            var backupDir = BackupManager.BackupServerArtifacts(serverDir);

            Assert.True(Directory.Exists(backupDir));
            Assert.StartsWith("backup-", Path.GetFileName(backupDir));
            Assert.True(File.Exists(Path.Combine(backupDir, "localhost.crt")));
            Assert.True(File.Exists(Path.Combine(backupDir, "localhost.key")));
            Assert.Equal("cert-data", File.ReadAllText(Path.Combine(backupDir, "localhost.crt")));
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void BackupServerArtifacts_UsesProvidedTimestamp()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            File.WriteAllText(Path.Combine(serverDir, "test.txt"), "data");

            var timestamp = new DateTime(2025, 3, 15, 14, 30, 45);
            var backupDir = BackupManager.BackupServerArtifacts(serverDir, timestamp);

            Assert.Equal("backup-20250315-143045", Path.GetFileName(backupDir));
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void BackupServerArtifacts_DoesNotCopySubdirectoryContents()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            File.WriteAllText(Path.Combine(serverDir, "localhost.crt"), "cert");
            var subDir = Path.Combine(serverDir, "subdir");
            Directory.CreateDirectory(subDir);
            File.WriteAllText(Path.Combine(subDir, "nested.txt"), "nested");

            var backupDir = BackupManager.BackupServerArtifacts(serverDir);

            // Only top-level files should be copied
            Assert.True(File.Exists(Path.Combine(backupDir, "localhost.crt")));
            Assert.False(File.Exists(Path.Combine(backupDir, "nested.txt")));
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void PruneBackups_KeepsLatestN_RemovesOldest()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            // Create 7 backup directories with deterministic names
            for (int i = 1; i <= 7; i++)
            {
                var name = $"backup-2025030{i}-120000";
                var dir = Path.Combine(serverDir, name);
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "marker.txt"), $"backup-{i}");
            }

            var pruned = BackupManager.PruneBackups(serverDir, keepCount: 5);

            // Should have pruned the 2 oldest (backup-1 and backup-2)
            Assert.Equal(2, pruned.Count);
            Assert.Contains(pruned, p => Path.GetFileName(p) == "backup-20250301-120000");
            Assert.Contains(pruned, p => Path.GetFileName(p) == "backup-20250302-120000");

            // Verify remaining
            var remaining = BackupManager.ListBackups(serverDir);
            Assert.Equal(5, remaining.Count);
            Assert.DoesNotContain(remaining, d => Path.GetFileName(d) == "backup-20250301-120000");
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void PruneBackups_NoPruningWhenUnderLimit()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            for (int i = 1; i <= 3; i++)
            {
                Directory.CreateDirectory(Path.Combine(serverDir, $"backup-2025030{i}-120000"));
            }

            var pruned = BackupManager.PruneBackups(serverDir, keepCount: 5);

            Assert.Empty(pruned);
            Assert.Equal(3, BackupManager.ListBackups(serverDir).Count);
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void PruneBackups_ExactlyAtLimit_NoPruning()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            for (int i = 1; i <= 5; i++)
            {
                Directory.CreateDirectory(Path.Combine(serverDir, $"backup-2025030{i}-120000"));
            }

            var pruned = BackupManager.PruneBackups(serverDir, keepCount: 5);

            Assert.Empty(pruned);
            Assert.Equal(5, BackupManager.ListBackups(serverDir).Count);
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void ListBackups_ReturnsNewestFirst()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            Directory.CreateDirectory(Path.Combine(serverDir, "backup-20250301-120000"));
            Directory.CreateDirectory(Path.Combine(serverDir, "backup-20250315-120000"));
            Directory.CreateDirectory(Path.Combine(serverDir, "backup-20250310-120000"));

            var backups = BackupManager.ListBackups(serverDir);

            Assert.Equal(3, backups.Count);
            Assert.Equal("backup-20250315-120000", Path.GetFileName(backups[0]));
            Assert.Equal("backup-20250310-120000", Path.GetFileName(backups[1]));
            Assert.Equal("backup-20250301-120000", Path.GetFileName(backups[2]));
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }

    [Fact]
    public void ListBackups_ReturnsEmptyForNonexistentDir()
    {
        var backups = BackupManager.ListBackups("/nonexistent/path");
        Assert.Empty(backups);
    }

    [Fact]
    public void ListBackups_IgnoresNonBackupDirectories()
    {
        var serverDir = CreateTempServerDir();
        try
        {
            Directory.CreateDirectory(Path.Combine(serverDir, "backup-20250301-120000"));
            Directory.CreateDirectory(Path.Combine(serverDir, "other-dir"));
            Directory.CreateDirectory(Path.Combine(serverDir, "logs"));

            var backups = BackupManager.ListBackups(serverDir);

            Assert.Single(backups);
        }
        finally
        {
            CleanupDir(serverDir);
        }
    }
}
