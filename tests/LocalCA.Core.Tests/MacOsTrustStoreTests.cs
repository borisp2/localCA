using NSubstitute;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class MacOsTrustStoreTests
{
    private static IProcessRunner MockRunner(
        Func<string, string, (int ExitCode, string Output)> handler)
    {
        var runner = Substitute.For<IProcessRunner>();
        runner.Run(Arg.Any<string>(), Arg.Any<string>())
            .Returns(ci => handler(ci.ArgAt<string>(0), ci.ArgAt<string>(1)));
        return runner;
    }

    // ── ImportCaCertificate ────────────────────────────────────────

    [Fact]
    public void ImportCaCertificate_SystemKeychainSucceeds_ReturnsTrue()
    {
        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("add-trusted-cert") && args.Contains("System.keychain"))
                return (0, "");
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        var (cert, key) = CertificateAuthority.CreateRootCa("Test", validDays: 30, keySizeBits: 2048);
        try
        {
            Assert.True(store.ImportCaCertificate(cert));
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ImportCaCertificate_SystemFails_FallsBackToUserKeychain()
    {
        int callCount = 0;
        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("add-trusted-cert"))
            {
                callCount++;
                // First call (System Keychain) fails, second (user keychain) succeeds
                return callCount == 1 ? (1, "authorization denied") : (0, "");
            }
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        var (cert, key) = CertificateAuthority.CreateRootCa("Test", validDays: 30, keySizeBits: 2048);
        try
        {
            Assert.True(store.ImportCaCertificate(cert));
            Assert.Equal(2, callCount);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ImportCaCertificate_BothKeychainsFail_ReturnsFalse()
    {
        var runner = MockRunner((file, args) => (1, "authorization denied"));

        var store = new MacOsTrustStore (runner);
        var (cert, key) = CertificateAuthority.CreateRootCa("Test", validDays: 30, keySizeBits: 2048);
        try
        {
            Assert.False(store.ImportCaCertificate(cert));
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ImportCaCertificate_PassesCorrectFlags()
    {
        string? capturedArgs = null;
        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("System.keychain"))
                capturedArgs = args;
            return (0, "");
        });

        var store = new MacOsTrustStore (runner);
        var (cert, key) = CertificateAuthority.CreateRootCa("Test", validDays: 30, keySizeBits: 2048);
        try
        {
            store.ImportCaCertificate(cert);

            Assert.NotNull(capturedArgs);
            Assert.Contains("add-trusted-cert", capturedArgs);
            Assert.Contains("-d", capturedArgs);
            Assert.Contains("admin", capturedArgs);
            Assert.Contains("-r", capturedArgs);
            Assert.Contains("trustRoot", capturedArgs);
            Assert.Contains("-p", capturedArgs);
            Assert.Contains("ssl", capturedArgs);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    // ── IsCertificateTrusted ──────────────────────────────────────

    [Fact]
    public void IsCertificateTrusted_FoundInSystemKeychain_ReturnsTrue()
    {
        const string thumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
        var securityOutput = $"""
            keychain: "/Library/Keychains/System.keychain"
            version: 256
            class: 0x80001000
            SHA-1 hash: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12
            """;

        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate") && args.Contains("System.keychain"))
                return (0, securityOutput);
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        Assert.True(store.IsCertificateTrusted(thumbprint));
    }

    [Fact]
    public void IsCertificateTrusted_NotFound_ReturnsFalse()
    {
        var securityOutput = """
            keychain: "/Library/Keychains/System.keychain"
            version: 256
            SHA-1 hash: 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00
            """;

        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate"))
                return (0, securityOutput);
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        Assert.False(store.IsCertificateTrusted("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    [Fact]
    public void IsCertificateTrusted_SecurityCommandFails_ReturnsFalse()
    {
        var runner = MockRunner((_, _) => (1, ""));

        var store = new MacOsTrustStore (runner);
        Assert.False(store.IsCertificateTrusted("ABCDEF1234567890ABCDEF1234567890ABCDEF12"));
    }

    // ── RemoveCaCertificate ───────────────────────────────────────

    [Fact]
    public void RemoveCaCertificate_CertFoundAndRemoved_ReturnsTrue()
    {
        const string thumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
        var findOutput = $"""
            SHA-1 hash: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12
            -----BEGIN CERTIFICATE-----
            MIIBkTCB+wIUYH/0wBgHHUhJHMC/kGGe2l0F0j8wDQYJKoZIhvcNAQELBQAwFDES
            MBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTIzMDEwMTAwMDAwMFoXDTI0MDEwMTAwMMDow
            -----END CERTIFICATE-----
            """;

        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate") && args.Contains("-p"))
                return (0, findOutput);
            if (file == "security" && args.Contains("remove-trusted-cert"))
                return (0, "");
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        Assert.True(store.RemoveCaCertificate(thumbprint));
    }

    [Fact]
    public void RemoveCaCertificate_CertNotFound_ReturnsFalse()
    {
        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate"))
                return (0, "SHA-1 hash: 11 22 33 44 55 66 77 88 99 00 11 22 33 44 55 66 77 88 99 00\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        Assert.False(store.RemoveCaCertificate("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    // ── RemoveBySubject ───────────────────────────────────────────

    [Fact]
    public void RemoveBySubject_FindsAndRemovesMatchingCerts_ReturnsCount()
    {
        var findBySubjectOutput = """
            SHA-1 hash: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12
            """;

        var findWithPemOutput = """
            SHA-1 hash: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12
            -----BEGIN CERTIFICATE-----
            MIIBkTCB+wIUYH/0wBgHHUhJHMC/kGGe2l0F0j8wDQYJKoZIhvcNAQELBQAwFDES
            MBAGA1UEAwwJVGVzdCBDZXJ0MB4XDTIzMDEwMTAwMDAwMFoXDTI0MDEwMTAwMDBaw
            -----END CERTIFICATE-----
            """;

        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate"))
            {
                // Only return matches from System Keychain; user keychain returns nothing
                if (!args.Contains("System.keychain"))
                    return (1, "");
                if (args.Contains("-p"))
                    return (0, findWithPemOutput);
                return (0, findBySubjectOutput);
            }
            if (file == "security" && args.Contains("remove-trusted-cert"))
                return (0, "");
            return (1, "");
        });

        var store = new MacOsTrustStore(runner);
        var removed = store.RemoveBySubject("Test Root CA");

        Assert.Equal(1, removed);
    }

    [Fact]
    public void RemoveBySubject_NoCertsFound_ReturnsZero()
    {
        var runner = MockRunner((file, args) =>
        {
            if (file == "security" && args.Contains("find-certificate"))
                return (1, "The specified item could not be found in the keychain.");
            return (1, "");
        });

        var store = new MacOsTrustStore (runner);
        Assert.Equal(0, store.RemoveBySubject("Nonexistent CA"));
    }

    // ── ExtractPemForThumbprint (internal helper) ─────────────────

    [Fact]
    public void ExtractPemForThumbprint_MatchingHash_ReturnsPem()
    {
        var output = """
            SHA-1 hash: AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD
            -----BEGIN CERTIFICATE-----
            MIIBfirstcert
            -----END CERTIFICATE-----
            SHA-1 hash: AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12
            -----BEGIN CERTIFICATE-----
            MIIBsecondcert
            -----END CERTIFICATE-----
            """;

        var pem = MacOsTrustStore.ExtractPemForThumbprint(output, "ABCDEF1234567890ABCDEF1234567890ABCDEF12");

        Assert.NotNull(pem);
        Assert.Contains("MIIBsecondcert", pem);
        Assert.DoesNotContain("MIIBfirstcert", pem);
    }

    [Fact]
    public void ExtractPemForThumbprint_NoMatch_ReturnsNull()
    {
        var output = """
            SHA-1 hash: AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD
            -----BEGIN CERTIFICATE-----
            MIIBtest
            -----END CERTIFICATE-----
            """;

        var pem = MacOsTrustStore.ExtractPemForThumbprint(output, "0000000000000000000000000000000000000000");

        Assert.Null(pem);
    }

    // ── TrustStoreFactory ─────────────────────────────────────────

    [Fact]
    public void TrustStoreFactory_ReturnsNonNullOnSupportedPlatform()
    {
        // This test verifies the factory returns an implementation
        // on the current platform. On non-Windows/macOS it returns null.
        var store = TrustStoreFactory.Create();

        if (OperatingSystem.IsWindows())
            Assert.IsType<WindowsTrustStore>(store);
        else if (OperatingSystem.IsMacOS())
            Assert.IsType<MacOsTrustStore>(store);
        else
            Assert.Null(store);
    }
}
