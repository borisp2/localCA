namespace LocalCA.Core;

/// <summary>
/// Orchestrates the status operation: checks whether CA/server artifacts
/// exist and reports certificate metadata.
/// </summary>
public sealed class StatusCommand
{
    public string RootDir { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA");

    public int Execute()
    {
        if (!Directory.Exists(RootDir))
        {
            Console.Error.WriteLine($"LocalCA directory not found: {RootDir}");
            return 1;
        }

        ITrustStore? trustStore = null;
        if (OperatingSystem.IsWindows())
            trustStore = new WindowsTrustStore();

        var report = CertificateStatusReporter.GetStatus(RootDir, trustStore);
        Console.Write(report.FormatReport());

        // Exit 1 if core artifacts are missing
        bool healthy = report.CaCertificate.Exists
                    && report.ServerCertificate.Exists
                    && report.CaKeyExists
                    && report.ServerKeyExists;

        return healthy ? 0 : 1;
    }
}
