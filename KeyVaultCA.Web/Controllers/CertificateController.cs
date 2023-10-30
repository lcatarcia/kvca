using KeyVaultCa.Core;
using KeyVaultCa.Core.Models;
using KeyVaultCA.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultCA.Web.Controllers
{
	public class CertificateController : BaseCertificateController
	{
		private readonly ILogger _logger;
		private readonly IKeyVaultCertificateProvider _keyVaultCertProvider;
		private readonly EstConfiguration _configuration;

		public CertificateController(
			ILogger<CertificateController> logger,
			IKeyVaultCertificateProvider certificateProvider,
			EstConfiguration configuration) : base(logger, certificateProvider, configuration)
		{
			_logger = logger;
			_keyVaultCertProvider = certificateProvider;
			_configuration = configuration;
		}
		public IActionResult Index()
		{
			CertificateSigningRequest request = new()
			{
				CommonName = "SIAG",
				Country = "Italy",
				Email = string.Empty,
				KeySize = 4096,
				Locality = "Bolzano",
				Organization = "SIAG",
				OrganizationUnit = "SIAG",
				State = "Trentino Alto Adige",
				SubjectAlternativeName = "SIAG",
				StartDate = DateTime.Now,
				EndDate = DateTime.Now.AddMonths(48),
			};

			SignResponse signResponse = new() { Csr = request };
			return View(signResponse);
		}

		[HttpPost]
		public async Task<IActionResult> Index(CertificateSigningRequest csrRequest)
		{
			_logger.LogDebug($"Call create CSR certificate and sign endpoint. Certificate name = {csrRequest.CertificateName}");
			try
			{
				string issuerCAName = _configuration.IssuingCA;
				PublicKey publicKey = (await GetPublicKeyList())?.FirstOrDefault() ?? null;
				X509Certificate2 result = await _keyVaultCertProvider.CreateCsrCertificateAndSignAsync(csrRequest, publicKey, issuerCAName);


				string pkcs7 = EncodeCertificatesAsPkcs7(new[] { result });

				SignResponse signResponse = new()
				{
					Csr = csrRequest,
					Result = pkcs7
				};
				return View(signResponse);
				//return Ok(pkcs7);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "GetPublicKey error");
				return BadRequest(ex.Message);
			}
		}
	}
}
