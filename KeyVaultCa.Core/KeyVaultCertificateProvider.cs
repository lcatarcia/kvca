// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Azure;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core.Models;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCa.Core
{
	public class KeyVaultCertificateProvider : IKeyVaultCertificateProvider
	{
		private readonly KeyVaultServiceClient _keyVaultServiceClient;
		private readonly ILogger _logger;

		public KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILogger<KeyVaultCertificateProvider> logger)
		{
			_keyVaultServiceClient = keyVaultServiceClient;
			_logger = logger;
		}

		public async Task CreateCACertificateAsync(string issuerCertificateName, string subject, int certPathLength)
		{
			int certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(issuerCertificateName).ConfigureAwait(false);

			if (certVersions != 0)
			{
				_logger.LogInformation("A certificate with the specified issuer name {name} already exists.", issuerCertificateName);
			}

			else
			{
				_logger.LogInformation("No existing certificate found, starting to create a new one.");
				DateTime notBefore = DateTime.UtcNow.AddDays(-1);
				await _keyVaultServiceClient.CreateCACertificateAsync(
						issuerCertificateName,
						subject,
						notBefore,
						notBefore.AddMonths(48),
						4096,
						256,
						certPathLength);
				_logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", issuerCertificateName, certPathLength);
			}
		}

		public async Task<X509Certificate2> CreateCsrCertificateAndSignAsync(
			CertificateSigningRequest csrRequest,
			PublicKey publicKey,
			string issuerCAName)
		{
			int certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(csrRequest.CertificateName).ConfigureAwait(false);
			X509Certificate2 result = null;

			if (certVersions != 0)
			{
				_logger.LogInformation("A certificate with the specified issuer name {name} already exists.", csrRequest.CertificateName);
			}

			else
			{
				_logger.LogInformation("No existing certificate found, starting to create a new one.");
				DateTime notBefore = csrRequest.StartDate != null ? csrRequest.StartDate.Value : DateTime.UtcNow.AddDays(-1);
				DateTime notAfter = csrRequest.EndDate != null ? csrRequest.EndDate.Value : notBefore.AddMonths(48);
				string subject = $"C={csrRequest.Country}, ST={csrRequest.State}, L={csrRequest.Locality}, O={csrRequest.Organization}, OU={csrRequest.OrganizationUnit}, CN={csrRequest.CommonName}";
				result = await _keyVaultServiceClient.CreateCsrCertificateAndSignAsync(
						csrRequest.CertificateName,
						publicKey,
						issuerCAName,
						subject,
						notBefore,
						notAfter,
						csrRequest.KeySize,
						256,
						1,
						csrRequest.UserService);

				_logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", csrRequest.CertificateName, csrRequest.KeySize);
			}
			return result;
		}

		public async Task<byte[]> CreateCsrCertificateAsync(CertificateSigningRequest csrRequest, PublicKey publicKey)
		{
			int certVersions = await _keyVaultServiceClient.GetCertificateVersionsAsync(csrRequest.CertificateName).ConfigureAwait(false);
			byte[] result = null;

			if (certVersions != 0)
			{
				_logger.LogInformation("A certificate with the specified issuer name {name} already exists.", csrRequest.CertificateName);
			}

			else
			{
				_logger.LogInformation("No existing certificate found, starting to create a new one.");
				DateTime notBefore = DateTime.UtcNow.AddDays(-1);
				//result = await _keyVaultServiceClient.CreateCsrCertificateAsync(
				//        issuerCertificateName,
				//        subject,
				//        notBefore,
				//        notBefore.AddMonths(48),
				//        4096,
				//        256,
				//        certPathLength);

				result = await _keyVaultServiceClient.CreateCsrCertificateAsync(csrRequest, publicKey);
				_logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", csrRequest.CertificateName, csrRequest.KeySize);
			}
			return result;
		}

		public async Task<Response<X509Certificate2>> DownloadCertificateAsync(string name)
			=> await _keyVaultServiceClient.DownloadCertificateAsync(name);

		public async Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName)
		{
			Response<KeyVaultCertificateWithPolicy> certBundle = await _keyVaultServiceClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);
			return new X509Certificate2(certBundle.Value.Cer);
		}

		public async Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames)
		{
			List<X509Certificate2> certs = new List<X509Certificate2>();

			foreach (string issuerName in certNames)
			{
				_logger.LogDebug("Call GetPublicCertificatesByName method with following certificate name: {name}.", issuerName);
				X509Certificate2 cert = await GetCertificateAsync(issuerName).ConfigureAwait(false);

				if (cert != null)
				{
					certs.Add(cert);
				}
			}

			return certs;
		}

		public async Task<IList<X509Certificate2>> GetSignedCertificatesByName(IEnumerable<string> certNames)
		{
			List<X509Certificate2> certs = new List<X509Certificate2>();

			foreach (string issuerName in certNames)
			{
				_logger.LogDebug("Call GetSignedCertificatesByName method with following certificate name: {name}.", issuerName);
				X509Certificate2 cert = await GetCertificateAsync(issuerName).ConfigureAwait(false);

				if (cert != null)
				{
					certs.Add(cert);
				}
			}

			return certs;
		}

		/// <summary>
		/// Creates a KeyVault signed certficate from signing request.
		/// </summary>
		public async Task<X509Certificate2> SignRequestAsync(
			byte[] certificateRequest,
			string issuerCertificateName,
			int validityInDays,
			UserService userService = null,
			bool caCert = false)
		{
			_logger.LogInformation("Preparing certificate request with issuer name {name}, {days} days validity period and 'is a CA certificate' flag set to {flag}.", issuerCertificateName, validityInDays, caCert);

			Pkcs10CertificationRequest pkcs10CertificationRequest = new Pkcs10CertificationRequest(certificateRequest);

			if (!pkcs10CertificationRequest.Verify())
			{
				_logger.LogError("CSR signature invalid.");
				throw new ArgumentException("CSR signature invalid.");
			}

			CertificationRequestInfo info = pkcs10CertificationRequest.GetCertificationRequestInfo();
			DateTime notBefore = DateTime.UtcNow.AddDays(-1);

			Response<KeyVaultCertificateWithPolicy> certBundle = await _keyVaultServiceClient.GetCertificateAsync(issuerCertificateName).ConfigureAwait(false);

			X509Certificate2 signingCert = new X509Certificate2(certBundle.Value.Cer);
			RSA publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);

			return await KeyVaultCertFactory.CreateSignedCertificate(
				info.Subject.ToString(),
				2048,
				notBefore,
				notBefore.AddDays(validityInDays),
				256,
				signingCert,
				publicKey,
				new KeyVaultSignatureGenerator(_keyVaultServiceClient.Credential, certBundle.Value.KeyId, signingCert),
				userService,
				caCert
				);
		}
	}
}