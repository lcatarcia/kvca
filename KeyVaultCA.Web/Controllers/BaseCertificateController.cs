﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System;
using KeyVaultCa.Core;
using Microsoft.Extensions.Logging;
using System.Text;
using KeyVaultCA.Web.RoleManager;

namespace KeyVaultCA.Web.Controllers
{
	public class BaseCertificateController : Controller
	{
		private readonly ILogger _logger;
		private readonly IKeyVaultCertificateProvider _keyVaultCertProvider;
		private readonly EstConfiguration _configuration;
		private readonly RoleManagerConfiguration _roleManagerConfiguration;
		private readonly Caller _caller;

		public BaseCertificateController(
			ILogger<CertificateController> logger,
			IKeyVaultCertificateProvider certificateProvider,
			EstConfiguration configuration,
			Caller caller,
			RoleManagerConfiguration roleManagerConfiguration)
		{
			_logger = logger;
			_keyVaultCertProvider = certificateProvider;
			_configuration = configuration;
			_caller = caller;
			_roleManagerConfiguration = roleManagerConfiguration;
		}
		public async Task<List<PublicKey>> GetPublicKeyList()
		{
			List<PublicKey> publicKeys = new();
			try
			{
				IList<X509Certificate2> caCerts = await _keyVaultCertProvider.GetPublicCertificatesByName(new[] { _configuration.IssuingCA });

				foreach (X509Certificate2 cert in caCerts)
				{
					publicKeys.Add(cert.PublicKey);
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "GetPublicKeys error");
			}
			return publicKeys;
		}

		public string EncodeCertificatesAsPkcs7(X509Certificate2[] certs)
		{
			X509Certificate2Collection collection = new(certs);
			byte[] data = collection.Export(X509ContentType.Pkcs7);

			StringBuilder builder = new();
			builder.AppendLine(Convert.ToBase64String(data));

			return builder.ToString();
		}

		public byte[] EncodeCertificateAsPfx(X509Certificate2 certificate)
			=> certificate.Export(X509ContentType.Pfx);

		public byte[] EncodeCertificateAsPkcs12(X509Certificate2 certificate)
			=> certificate?.Export(X509ContentType.Pkcs12);

		public async Task<IList<X509Certificate2>> GetCertificatesByNameAsync(string name)
			=> await _keyVaultCertProvider.GetPublicCertificatesByName(new[] { name });
	}
}
