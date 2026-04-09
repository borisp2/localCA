using NSubstitute;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core.Tests;

public class MacTrustStoreTests
{
    private const string SystemKeychain = "/Library/Keychains/System.keychain";

    [Fact]
    public void ImportCaCertificate_SystemKeychainSuccess_ReturnsTrue()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("add-trusted-cert") && a.Contains(SystemKeychain)))
            .Returns((0, ""));

        var store = new MacTrustStore(mockRunner);

        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
        try
        {
            var result = store.ImportCaCertificate(cert);

            Assert.True(result);
            mockRunner.Received(1).Run("security", Arg.Is<string>(a => a.Contains("add-trusted-cert") && a.Contains(SystemKeychain)));
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void ImportCaCertificate_SystemFails_FallsBackToLoginKeychain()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        // System keychain fails
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("add-trusted-cert") && a.Contains(SystemKeychain)))
            .Returns((1, "error"));
        // Login keychain succeeds
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("add-trusted-cert") && !a.Contains(SystemKeychain)))
            .Returns((0, ""));

        var store = new MacTrustStore(mockRunner);

        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
        try
        {
            var result = store.ImportCaCertificate(cert);

            Assert.True(result);
            // Should have tried both
            mockRunner.Received(2).Run("security", Arg.Any<string>());
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
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Any<string>()).Returns((1, "error"));

        var store = new MacTrustStore(mockRunner);

        var (cert, key) = CertificateAuthority.CreateRootCa("TestApp", validDays: 30, keySizeBits: 2048);
        try
        {
            var result = store.ImportCaCertificate(cert);

            Assert.False(result);
        }
        finally
        {
            key.Dispose();
            cert.Dispose();
        }
    }

    [Fact]
    public void RemoveCaCertificate_Found_DeletesAndReturnsTrue()
    {
        var thumbprint = "AABBCCDD11223344EEFF";
        var mockRunner = Substitute.For<IProcessRunner>();

        // find-certificate returns output containing the thumbprint
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate")))
            .Returns((0, $"SHA-1 hash: {thumbprint}\n    \"labl\"<blob>=\"LocalCA\""));

        // delete-certificate succeeds
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("delete-certificate")))
            .Returns((0, ""));

        var store = new MacTrustStore(mockRunner);

        var result = store.RemoveCaCertificate(thumbprint);

        Assert.True(result);
        mockRunner.Received(1).Run("security", Arg.Is<string>(a => a.Contains("delete-certificate")));
    }

    [Fact]
    public void RemoveCaCertificate_NotFound_ReturnsFalse()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate")))
            .Returns((0, "SHA-1 hash: XXXXXXXX\n"));

        var store = new MacTrustStore(mockRunner);

        var result = store.RemoveCaCertificate("NOTINTHEKEYCHAIN");

        Assert.False(result);
    }

    [Fact]
    public void IsCertificateTrusted_FoundInSystemKeychain_ReturnsTrue()
    {
        var thumbprint = "AABBCCDD11223344EEFF";
        var mockRunner = Substitute.For<IProcessRunner>();

        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate") && a.Contains(SystemKeychain)))
            .Returns((0, $"SHA-1 hash: {thumbprint}\n"));

        var store = new MacTrustStore(mockRunner);

        Assert.True(store.IsCertificateTrusted(thumbprint));
    }

    [Fact]
    public void IsCertificateTrusted_FoundInLoginKeychain_ReturnsTrue()
    {
        var thumbprint = "AABBCCDD11223344EEFF";
        var mockRunner = Substitute.For<IProcessRunner>();

        // Not in System keychain
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate") && a.Contains(SystemKeychain)))
            .Returns((0, "SHA-1 hash: XXXXXXXX\n"));

        // Found in login keychain
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate") && !a.Contains(SystemKeychain)))
            .Returns((0, $"SHA-1 hash: {thumbprint}\n"));

        var store = new MacTrustStore(mockRunner);

        Assert.True(store.IsCertificateTrusted(thumbprint));
    }

    [Fact]
    public void IsCertificateTrusted_NotFound_ReturnsFalse()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Any<string>())
            .Returns((0, "SHA-1 hash: XXXXXXXX\n"));

        var store = new MacTrustStore(mockRunner);

        Assert.False(store.IsCertificateTrusted("NOTFOUND123"));
    }

    [Fact]
    public void RemoveBySubject_FindsAndRemovesMatching()
    {
        var mockRunner = Substitute.For<IProcessRunner>();

        var findOutput = "SHA-1 hash: AAAA1111\n    \"labl\"<blob>=\"LocalCA\"\nSHA-1 hash: BBBB2222\n    \"labl\"<blob>=\"LocalCA\"";
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate") && a.Contains("-c")))
            .Returns((0, findOutput));

        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("delete-certificate")))
            .Returns((0, ""));

        var store = new MacTrustStore(mockRunner);

        var removed = store.RemoveBySubject("TestApp Localhost Root CA");

        Assert.Equal(2, removed);
        mockRunner.Received(2).Run("security", Arg.Is<string>(a => a.Contains("delete-certificate")));
    }

    [Fact]
    public void RemoveBySubject_NoMatches_ReturnsZero()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Is<string>(a => a.Contains("find-certificate")))
            .Returns((0, ""));

        var store = new MacTrustStore(mockRunner);

        var removed = store.RemoveBySubject("NonExistentApp");

        Assert.Equal(0, removed);
    }

    [Fact]
    public void RemoveBySubject_FindFails_ReturnsZero()
    {
        var mockRunner = Substitute.For<IProcessRunner>();
        mockRunner.Run("security", Arg.Any<string>())
            .Returns((1, "error"));

        var store = new MacTrustStore(mockRunner);

        var removed = store.RemoveBySubject("TestApp");

        Assert.Equal(0, removed);
    }
}
