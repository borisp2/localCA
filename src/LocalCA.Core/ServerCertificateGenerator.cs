using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Generates a server certificate signed by a CA, with SANs for localhost usage.
/// </summary>
public static class ServerCertificateGenerator
{
    public static X509Certificate2 CreateServerCertificate(
        X509Certificate2 caCert,
        int validDays = 825,
        int keySizeBits = 2048,
        IEnumerable<string>? additionalDnsNames = null)
    {
        var (cert, key) = CreateServerCertificateWithKey(caCert, validDays, keySizeBits, additionalDnsNames);
        key.Dispose();
        return cert;
    }

    public static (X509Certificate2 Certificate, RSA PrivateKey) CreateServerCertificateWithKey(
        X509Certificate2 caCert,
        int validDays = 825,
        int keySizeBits = 2048,
        IEnumerable<string>? additionalDnsNames = null)
    {
        var machineName = Environment.MachineName;
        var dnsNames = new List<string> { "localhost", machineName, $"{machineName}.local" };
        if (additionalDnsNames != null)
            dnsNames.AddRange(additionalDnsNames);

        var ipAddresses = new List<IPAddress>
        {
            IPAddress.Loopback,   // 127.0.0.1
            IPAddress.IPv6Loopback // ::1
        };

        return CreateServerCertificateWithKey(caCert, dnsNames, ipAddresses, validDays, keySizeBits);
    }

    public static X509Certificate2 CreateServerCertificate(
        X509Certificate2 caCert,
        IReadOnlyList<string> dnsNames,
        IReadOnlyList<IPAddress> ipAddresses,
        int validDays = 825,
        int keySizeBits = 2048)
    {
        var (cert, key) = CreateServerCertificateWithKey(caCert, dnsNames, ipAddresses, validDays, keySizeBits);
        key.Dispose();
        return cert;
    }

    /// <summary>
    /// Creates a server certificate and returns it together with a standalone
    /// RSA private key that is guaranteed to be exportable on all platforms.
    /// The returned RSA key is built from bytes captured before any
    /// certificate/PFX operation, so it is never affected by Windows CNG
    /// export restrictions.  Callers that need to export the private key PEM
    /// should use the returned RSA instance instead of
    /// <c>cert.GetRSAPrivateKey()</c>.
    /// </summary>
    public static (X509Certificate2 Certificate, RSA PrivateKey) CreateServerCertificateWithKey(
        X509Certificate2 caCert,
        IReadOnlyList<string> dnsNames,
        IReadOnlyList<IPAddress> ipAddresses,
        int validDays = 825,
        int keySizeBits = 2048)
    {
        using var serverKey = RSA.Create(keySizeBits);

        // Capture key bytes from the original software-backed handle BEFORE
        // it touches any certificate operation.  On Windows, CopyWithPrivateKey
        // / PFX round-trip can produce a CNG handle that refuses all export
        // operations (ExportPkcs8PrivateKey, ExportParameters, etc.).
        var rawKeyBytes = serverKey.ExportPkcs8PrivateKey();

        var subject = new X500DistinguishedName("CN=localhost");
        var request = new CertificateRequest(subject, serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, // serverAuth
                critical: false));

        // Build SAN extension
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dns in dnsNames)
            sanBuilder.AddDnsName(dns);
        foreach (var ip in ipAddresses)
            sanBuilder.AddIpAddress(ip);

        request.CertificateExtensions.Add(sanBuilder.Build());

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // Serial number
        var serial = new byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F; // Ensure positive

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(validDays);

        using var caPrivateKey = caCert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("CA certificate does not contain a private key.");

        var cert = request.Create(caCert, notBefore, notAfter, serial);

        // Combine with private key
        var certWithKey = cert.CopyWithPrivateKey(serverKey);

        // PFX round-trip so the cert is fully portable.
        // EphemeralKeySet keeps the private key in memory only (no Windows key-store
        // persistence), which avoids CNG non-exportable handle issues on Windows CI.
        var portableCert = new X509Certificate2(
            certWithKey.Export(X509ContentType.Pfx, ""),
            "",
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        // Build a standalone RSA key from the pre-captured bytes — guaranteed
        // exportable on all platforms, independent of CNG handle state.
        var exportableKey = RSA.Create();
        exportableKey.ImportPkcs8PrivateKey(rawKeyBytes, out _);

        return (portableCert, exportableKey);
    }
}
