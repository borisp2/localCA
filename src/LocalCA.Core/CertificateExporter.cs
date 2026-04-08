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
            // when created with X509KeyStorageFlags.Exportable.  Work around by
            // exporting the key parameters and re-importing into a new,
            // software-only RSA instance that is always exportable.
            var parameters = privateKey.ExportParameters(includePrivateParameters: true);
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
        X509Certificate2 caCert)
    {
        var sb = new StringBuilder();
        sb.AppendLine(serverCert.ExportCertificatePem());
        sb.AppendLine(caCert.ExportCertificatePem());

        var serverKey = serverCert.GetRSAPrivateKey();
        if (serverKey != null)
        {
            sb.AppendLine(ExportPrivateKeyPem(serverKey));
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
        X509Certificate2 serverCert)
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

        // Server private key
        var serverKey = serverCert.GetRSAPrivateKey()
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
            ExportFullchainPem(serverCert, caCert));
    }
}
