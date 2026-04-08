namespace LocalCA.Core;

/// <summary>
/// Orchestrates the verify operation: loads certs from disk and
/// validates the server certificate against the CA.
/// </summary>
public sealed class VerifyCommand
{
    public string RootDir { get; init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "LocalCA");

    public bool Verbose { get; init; }

    public int Execute()
    {
        var result = CertificateVerifier.Verify(RootDir);

        if (Verbose)
        {
            foreach (var detail in result.Details)
                Console.WriteLine($"  [OK]    {detail}");
        }

        foreach (var error in result.Errors)
            Console.Error.WriteLine($"  [FAIL]  {error}");

        Console.WriteLine();
        Console.WriteLine(result.IsValid ? "PASS" : "FAIL");
        Console.WriteLine(result.Summary);

        return result.IsValid ? 0 : 1;
    }
}
