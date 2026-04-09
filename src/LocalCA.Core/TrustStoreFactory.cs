namespace LocalCA.Core;

/// <summary>
/// Creates the platform-appropriate <see cref="ITrustStore"/> implementation.
/// Returns <c>null</c> on unsupported platforms.
/// </summary>
public static class TrustStoreFactory
{
    public static ITrustStore? Create()
    {
        if (OperatingSystem.IsWindows())
            return new WindowsTrustStore();

        if (OperatingSystem.IsMacOS())
            return new MacOsTrustStore();

        return null;
    }
}
