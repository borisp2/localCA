namespace LocalCA.Core;

/// <summary>
/// Creates the appropriate <see cref="ITrustStore"/> implementation for the current OS.
/// Returns null on platforms where no trust store implementation is available.
/// </summary>
public static class TrustStoreFactory
{
    /// <summary>
    /// Creates a trust store for the current platform.
    /// </summary>
    /// <returns>
    /// An <see cref="ITrustStore"/> for the current OS, or <c>null</c> if the
    /// platform is not supported.
    /// </returns>
    public static ITrustStore? Create()
    {
        if (OperatingSystem.IsWindows())
            return new WindowsTrustStore();

        if (OperatingSystem.IsMacOS())
            return new MacTrustStore();

        if (OperatingSystem.IsLinux())
            return new LinuxTrustStore();

        return null;
    }
}
