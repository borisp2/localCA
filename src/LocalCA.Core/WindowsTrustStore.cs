using System.Security.Cryptography.X509Certificates;

namespace LocalCA.Core;

/// <summary>
/// Windows trust store operations using X509Store APIs.
/// Imports/removes CA certificates from both LocalMachine and CurrentUser
/// Trusted Root Certification Authorities stores.
/// </summary>
public sealed class WindowsTrustStore : ITrustStore
{
    private static readonly StoreLocation[] Locations =
    {
        StoreLocation.LocalMachine,
        StoreLocation.CurrentUser
    };

    public bool ImportCaCertificate(X509Certificate2 certificate)
    {
        bool anySuccess = false;

        foreach (var location in Locations)
        {
            using var store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);
                anySuccess = true;
            }
            catch (Exception)
            {
                // LocalMachine may require elevation; continue with CurrentUser
            }
        }

        return anySuccess;
    }

    public bool RemoveCaCertificate(string thumbprint)
    {
        bool anyRemoved = false;

        foreach (var location in Locations)
        {
            using var store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var matches = store.Certificates.Find(
                    X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                foreach (var cert in matches)
                {
                    store.Remove(cert);
                    anyRemoved = true;
                    cert.Dispose();
                }
            }
            catch (Exception)
            {
                // May lack permissions for LocalMachine
            }
        }

        return anyRemoved;
    }

    public int RemoveBySubject(string subjectMatch)
    {
        int totalRemoved = 0;

        foreach (var location in Locations)
        {
            using var store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var matches = store.Certificates
                    .Where(c => c.Subject.Contains(subjectMatch, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var cert in matches)
                {
                    store.Remove(cert);
                    totalRemoved++;
                    cert.Dispose();
                }
            }
            catch (Exception)
            {
                // May lack permissions for LocalMachine
            }
        }

        return totalRemoved;
    }

    public bool IsCertificateTrusted(string thumbprint)
    {
        foreach (var location in Locations)
        {
            using var store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var matches = store.Certificates.Find(
                    X509FindType.FindByThumbprint, thumbprint, validOnly: false);

                if (matches.Count > 0)
                {
                    foreach (var cert in matches)
                        cert.Dispose();
                    return true;
                }
            }
            catch (Exception)
            {
                // Store may not be accessible
            }
        }

        return false;
    }
}
