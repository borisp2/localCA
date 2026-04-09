using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LocalCA.Core;

/// <summary>
/// Exports certificates and keys to PEM and PFX formats.
/// </summary>
public static class CertificateExporter
{
    public static string ExportCertificatePem(X509Certificate2 cert)
    {
        return cert.ExportCertificatePem();
    }

    public static string ExportPrivateKeyPem(RSA privateKey)
    {
        byte[] keyBytes;
        try
        {
            keyBytes = privateKey.ExportPkcs8PrivateKey();
        }
        catch (CryptographicException)
        {
            // On Windows, CNG-backed keys may refuse ExportPkcs8PrivateKey even
            // when created with X509KeyStorageFlags.Exportable.  Re-import the
            // key parameters into a fresh software-only RSA instance.
            // ExportParameters can also throw on some CNG handles, so try
            // ExportEncryptedPkcs8PrivateKey as a last resort — it reliably
            // works with CNG keys even when plain export methods fail.
            RSAParameters parameters;
            try
            {
                parameters = privateKey.ExportParameters(includePrivateParameters: true);
            }
            catch (CryptographicException)
            {
                // Last resort: use encrypted PKCS#8 export (supported by CNG),
                // then re-import into a software-only RSA to get plain bytes.
                var pbeParams = new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 1);
                var encryptedBytes = privateKey.ExportEncryptedPkcs8PrivateKey(
                    "export-temp"u8, pbeParams);
                using var reimported = RSA.Create();
                reimported.ImportEncryptedPkcs8PrivateKey(
                    "export-temp"u8, encryptedBytes, out _);
                keyBytes = reimported.ExportPkcs8PrivateKey();
                return new string(PemEncoding.Write("PRIVATE KEY", keyBytes));
            }

            using var exportable = RSA.Create();
            exportable.ImportParameters(parameters);
            keyBytes = exportable.ExportPkcs8PrivateKey();
        }

        return new string(PemEncoding.Write("PRIVATE KEY", keyBytes));
    }

    public static byte[] ExportPfx(X509Certificate2 cert, string password = "")
    {
        return cert.Export(X509ContentType.Pfx, password);
    }

    /// <summary>
    /// Creates a fullchain PEM containing server cert + CA cert + server private key.
    /// </summary>
    public static string ExportFullchainPem(
        X509Certificate2 serverCert,
        X509Certificate2 caCert,
        RSA? serverPrivateKey = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine(serverCert.ExportCertificatePem());
        sb.AppendLine(caCert.ExportCertificatePem());

        var keyToExport = serverPrivateKey ?? serverCert.GetRSAPrivateKey();
        if (keyToExport != null)
        {
            sb.AppendLine(ExportPrivateKeyPem(keyToExport));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Writes all certificate artifacts to the specified directory structure.
    /// </summary>
    public static void WriteArtifacts(
        string rootDir,
        X509Certificate2 caCert,
        RSA caPrivateKey,
        X509Certificate2 serverCert,
        RSA? serverPrivateKey = null)
    {
        var privateDir = Path.Combine(rootDir, "private");
        var certsDir = Path.Combine(rootDir, "certs");
        var serverDir = Path.Combine(rootDir, "server");

        // CA private key
        File.WriteAllText(
            Path.Combine(privateDir, "ca.key"),
            ExportPrivateKeyPem(caPrivateKey));

        // CA certificate
        File.WriteAllText(
            Path.Combine(certsDir, "ca.crt"),
            ExportCertificatePem(caCert));

        // Server private key — prefer the pre-captured exportable key when
        // provided; fall back to extracting from the certificate (which may
        // yield a non-exportable CNG handle on Windows).
        var serverKey = serverPrivateKey
            ?? serverCert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Server certificate has no private key.");
        File.WriteAllText(
            Path.Combine(serverDir, "localhost.key"),
            ExportPrivateKeyPem(serverKey));

        // Server certificate
        File.WriteAllText(
            Path.Combine(serverDir, "localhost.crt"),
            ExportCertificatePem(serverCert));

        // PFX bundle
        File.WriteAllBytes(
            Path.Combine(serverDir, "localhost.pfx"),
            ExportPfx(serverCert));

        // Fullchain PEM
        File.WriteAllText(
            Path.Combine(serverDir, "localhost-fullchain.pem"),
            ExportFullchainPem(serverCert, caCert, serverPrivateKey));
    }
}
