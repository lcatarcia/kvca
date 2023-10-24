// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core.Models;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
    /// <summary>
    /// The KeyVault service client.
    /// </summary>
    public class KeyVaultServiceClient
    {
        private CertificateClient _certificateClient;
        private readonly ILogger _logger;
        public DefaultAzureCredential Credential { get; set; }

        /// <summary>
        /// Create the certificate client for managing certificates in Key Vault, using developer authentication locally or managed identity in the cloud.
        /// </summary>
        public KeyVaultServiceClient(EstConfiguration config, DefaultAzureCredential credential, ILogger<KeyVaultServiceClient> logger)
        {
            _certificateClient = new CertificateClient(new Uri(config.KeyVaultUrl), credential);
            _logger = logger;
            Credential = credential;
        }

        internal async Task<X509Certificate2> CreateCACertificateAsync(
                string id,
                string subject,
                DateTime notBefore,
                DateTime notAfter,
                int keySize,
                int hashSize,
                int certPathLength,
                CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", id);
                CertificateOperation op = await _certificateClient.GetCertificateOperationAsync(id);
                await op.DeleteAsync();
            }
            catch
            {
                // intentionally ignore errors 
            }

            string caTempCertIdentifier = null;

            try
            {
                // create policy for self signed certificate with a new key
                var policySelfSignedNewKey = CreateCertificatePolicy(subject, keySize, true, false);

                CertificateOperation newCertificateOperation = await _certificateClient.StartCreateCertificateAsync(id, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", id);

                Response<KeyVaultCertificateWithPolicy> createdCertificateBundle = await _certificateClient.GetCertificateAsync(id).ConfigureAwait(false);
                caTempCertIdentifier = createdCertificateBundle.Value.Id.ToString();

                _logger.LogDebug("Temporary certificate identifier is {certIdentifier}.", caTempCertIdentifier);
                _logger.LogDebug("Temporary certificate backing key identifier is {key}.", createdCertificateBundle.Value.KeyId);

                // create policy for unknown issuer and reuse key
                var policyUnknownReuse = CreateCertificatePolicy(subject, keySize, false, true);
                var tags = CreateCertificateTags(id, false);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                CertificateOperation createResult = await _certificateClient.StartCreateCertificateAsync(id, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                Pkcs10CertificationRequest pkcs10CertificationRequest = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(createResult.Properties.Csr);
                var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }

                // create the self signed root CA certificate
                _logger.LogDebug("Create the self signed root CA certificate.");
                RSA publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                X509Certificate2 signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                    subject,
                    (ushort)keySize,
                    notBefore,
                    notAfter,
                    (ushort)hashSize,
                    null,
                    publicKey,
                    new KeyVaultSignatureGenerator(Credential, createdCertificateBundle.Value.KeyId, null),
                    true,
                    certPathLength);

                // merge Root CA cert with the signed certificate
                _logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                MergeCertificateOptions options = new MergeCertificateOptions(id, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                Response<KeyVaultCertificateWithPolicy> mergeResult = await _certificateClient.MergeCertificateAsync(options);

                return signedcert;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new Root CA certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse = _certificateClient.GetCertificate(caTempCertIdentifier);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _certificateClient.UpdateCertificatePropertiesAsync(certificateProperties);
                    }
                    catch
                    {
                        // intentionally ignore error
                    }
                }
            }
        }

        internal async Task<X509Certificate2> CreateCsrCertificateAndSignAsync(
                string id,
                string subject,
                DateTime notBefore,
                DateTime notAfter,
                int keySize,
                int hashSize,
                int certPathLength,
                CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", id);
                CertificateOperation op = await _certificateClient.GetCertificateOperationAsync(id);
                await op.DeleteAsync();
            }
            catch
            {
                // intentionally ignore errors 
            }

            string caTempCertIdentifier = null;

            try
            {
                // create policy for self signed certificate with a new key
                CertificatePolicy policySelfSignedNewKey = CreateCertificatePolicy(subject, keySize, true, false);

                CertificateOperation newCertificateOperation = await _certificateClient.StartCreateCertificateAsync(id, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", id);

                Response<KeyVaultCertificateWithPolicy> createdCertificateBundle = await _certificateClient.GetCertificateAsync(id).ConfigureAwait(false);
                caTempCertIdentifier = createdCertificateBundle.Value.Id.ToString();

                _logger.LogDebug("Temporary certificate identifier is {certIdentifier}.", caTempCertIdentifier);
                _logger.LogDebug("Temporary certificate backing key identifier is {key}.", createdCertificateBundle.Value.KeyId);

                // create policy for unknown issuer and reuse key
                var policyUnknownReuse = CreateCertificatePolicy(subject, keySize, false, true);
                var tags = CreateCertificateTags(id, false);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                CertificateOperation createResult = await _certificateClient.StartCreateCertificateAsync(id, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                Pkcs10CertificationRequest pkcs10CertificationRequest = new(createResult.Properties.Csr);
                var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }

                // create the self signed root CA certificate
                _logger.LogDebug("Create the self signed root CA certificate.");
                RSA publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                X509Certificate2 signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                    subject,
                    (ushort)keySize,
                    notBefore,
                    notAfter,
                    (ushort)hashSize,
                    null,
                    publicKey,
                    new KeyVaultSignatureGenerator(Credential, createdCertificateBundle.Value.KeyId, null),
                    true,
                    certPathLength);

                // merge Root CA cert with the signed certificate
                _logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                MergeCertificateOptions options = new(id, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                Response<KeyVaultCertificateWithPolicy> mergeResult = await _certificateClient.MergeCertificateAsync(options);

                return signedcert;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new Root CA certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse = _certificateClient.GetCertificate(caTempCertIdentifier);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _certificateClient.UpdateCertificatePropertiesAsync(certificateProperties);
                    }
                    catch
                    {
                        // intentionally ignore error
                    }
                }
            }
        }

        internal async Task<Response<X509Certificate2>> DownloadCertificateAsync(string name)
        {
            Response<X509Certificate2> certificate = await _certificateClient.DownloadCertificateAsync(new DownloadCertificateOptions(name)
            {
                KeyStorageFlags = X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable
            });

            return certificate;
        }

        //internal async Task<byte[]> CreateCsrCertificateAsync(
        //        string id,
        //        string subject,
        //        DateTime notBefore,
        //        DateTime notAfter,
        //        int keySize,
        //        int hashSize,
        //        int certPathLength,
        //        CancellationToken ct = default)
        //{
        internal async Task<byte[]> CreateCsrCertificateAsync(
                CreateCsrRequest csrRequest,
                CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", csrRequest.CertificateName);
                CertificateOperation op = await _certificateClient.GetCertificateOperationAsync(csrRequest.CertificateName);
                await op.DeleteAsync();
            }
            catch
            {
                // intentionally ignore errors 
            }

            string caTempCertIdentifier = null;

            try
            {
                string subject = $"C={csrRequest.Country}, ST={csrRequest.State}, L={csrRequest.Locality}, O={csrRequest.Organization}, OU={csrRequest.OrganizationUnit}, CN={csrRequest.CommonName}";

                // create policy for self signed certificate with a new key
                CertificatePolicy policySelfSignedNewKey = CreateCertificatePolicy(subject, csrRequest.KeySize, true, false);

                CertificateOperation newCertificateOperation = await _certificateClient.StartCreateCertificateAsync(csrRequest.CertificateName, policySelfSignedNewKey, true, null, ct).ConfigureAwait(false);
                await newCertificateOperation.WaitForCompletionAsync(ct).ConfigureAwait(false);

                if (!newCertificateOperation.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                _logger.LogDebug("Creation of temporary self signed certificate with id {id} completed.", csrRequest.CertificateName);

                Response<KeyVaultCertificateWithPolicy> createdCertificateBundle = await _certificateClient.GetCertificateAsync(csrRequest.CertificateName).ConfigureAwait(false);
                caTempCertIdentifier = createdCertificateBundle.Value.Id.ToString();

                _logger.LogDebug("Temporary certificate identifier is {certIdentifier}.", caTempCertIdentifier);
                _logger.LogDebug("Temporary certificate backing key identifier is {key}.", createdCertificateBundle.Value.KeyId);

                // create policy for unknown issuer and reuse key
                CertificatePolicy policyUnknownReuse = CreateCertificatePolicy(subject, csrRequest.KeySize, false, true);
                Dictionary<string, string> tags = CreateCertificateTags(csrRequest.CertificateName, true);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                CertificateOperation createResult = await _certificateClient.StartCreateCertificateAsync(csrRequest.CertificateName, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                Pkcs10CertificationRequest pkcs10CertificationRequest = new(createResult.Properties.Csr);
                CertificationRequestInfo info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }

                return createResult.Properties.Csr;

                //// create the self signed root CA certificate
                //_logger.LogDebug("Create the self signed root CA certificate.");
                //RSA publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                //X509Certificate2 signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                //subject,
                //    (ushort)keySize,
                //    notBefore,
                //    notAfter,
                //    (ushort)hashSize,
                //    null,
                //    publicKey,
                //    new KeyVaultSignatureGenerator(Credential, createdCertificateBundle.Value.KeyId, null),
                //    true,
                //    certPathLength);

                //// merge Root CA cert with the signed certificate
                //_logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                //MergeCertificateOptions options = new MergeCertificateOptions(id, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                //Response<KeyVaultCertificateWithPolicy> mergeResult = await _certificateClient.MergeCertificateAsync(options);

                //return signedcert;
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new Root CA certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse = _certificateClient.GetCertificate(caTempCertIdentifier);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _certificateClient.UpdateCertificatePropertiesAsync(certificateProperties);
                    }
                    catch
                    {
                        // intentionally ignore error
                    }
                }
            }
            //X509Certificate2 certificate = new X509Certificate2(
            //    Convert.FromBase64String(csr),
            //    (string)null,
            //    X509KeyStorageFlags.MachineKeySet 
            //    | X509KeyStorageFlags.PersistKeySet 
            //    | X509KeyStorageFlags.Exportable);
            //string b64 = Convert.ToBase64String(certificate.RawData);
            //byte[] rawData = Convert.FromBase64String(b64);
            //ImportCertificateOptions importCertificateOptions = new ImportCertificateOptions(csrRequest.CertificateName, rawData);
            //Response<KeyVaultCertificateWithPolicy> csrImportResult = await _certificateClient.ImportCertificateAsync(importCertificateOptions, ct);

            //return derEncodedCsr;


        }

        /// <summary>
        /// Get Certificate with Policy from Key Vault.
        /// </summary>
        internal async Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certName, CancellationToken ct = default)
        {
            return await _certificateClient.GetCertificateAsync(certName, ct).ConfigureAwait(false);
        }


        /// <summary>
        /// Get certificate versions for given certificate name.
        /// </summary>
        internal async Task<int> GetCertificateVersionsAsync(string certName)
        {
            var versions = 0;
            await foreach (CertificateProperties cert in _certificateClient.GetPropertiesOfCertificateVersionsAsync(certName))
            {
                versions++;
            }
            return versions;
        }

        private Dictionary<string, string> CreateCertificateTags(string id, bool trusted)
        {
            var tags = new Dictionary<string, string>
            {
                [id] = trusted ? "Trusted" : "Issuer"
            };

            _logger.LogDebug("Created certificate tags for certificate with id {id} and trusted flag set to {trusted}.", id, trusted);
            return tags;
        }

        private CertificatePolicy CreateCertificatePolicy(
            string subject,
            int keySize,
            bool selfSigned,
            bool reuseKey = false,
            bool exportable = false)
        {
            var issuerName = selfSigned ? "Self" : "Unknown";
            var policy = new CertificatePolicy(issuerName, subject)
            {
                Exportable = exportable,
                KeySize = keySize,
                KeyType = "RSA",
                ReuseKey = reuseKey,
                ContentType = CertificateContentType.Pkcs12
            };

            _logger.LogDebug("Created certificate policy for certificate with issuer name {issuerName}, self signed {selfSigned} and reused key {reuseKey}.", issuerName, selfSigned, reuseKey);
            return policy;
        }
    }
}