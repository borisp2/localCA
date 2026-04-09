namespace LocalCA.Core.Tests;

public class TrustStoreFactoryTests
{
    [Fact]
    public void Create_ReturnsNonNullOnSupportedPlatform()
    {
        // TrustStoreFactory.Create() should return a concrete implementation
        // on Windows, macOS, and Linux — essentially any CI/dev environment.
        var store = TrustStoreFactory.Create();

        if (OperatingSystem.IsWindows())
            Assert.IsType<WindowsTrustStore>(store);
        else if (OperatingSystem.IsMacOS())
            Assert.IsType<MacTrustStore>(store);
        else if (OperatingSystem.IsLinux())
            Assert.IsType<LinuxTrustStore>(store);
        else
            Assert.Null(store); // Unsupported platform
    }

    [Fact]
    public void Create_ReturnsCorrectTypeForCurrentPlatform()
    {
        var store = TrustStoreFactory.Create();

        // On any supported CI platform, we should get a trust store
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            Assert.NotNull(store);
            Assert.IsAssignableFrom<ITrustStore>(store);
        }
    }
}
