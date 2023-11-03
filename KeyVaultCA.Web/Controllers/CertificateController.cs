using KeyVaultCa.Core;
using KeyVaultCa.Core.Models;
using KeyVaultCA.Web.Models;
using KeyVaultCA.Web.RoleManager;
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
		private readonly Caller _caller;
		private readonly RoleManagerConfiguration _roleManagerConfiguration;

		public CertificateController(
			ILogger<CertificateController> logger,
			IKeyVaultCertificateProvider certificateProvider,
			EstConfiguration configuration,
			Caller caller,
			RoleManagerConfiguration roleManagerConfiguration) : base(logger, certificateProvider, configuration, caller, roleManagerConfiguration)
		{
			_logger = logger;
			_keyVaultCertProvider = certificateProvider;
			_configuration = configuration;
			_caller = caller;
			_roleManagerConfiguration = roleManagerConfiguration;
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

				string accessTokenUrl = $"https://{_roleManagerConfiguration.TenantName}.b2clogin.com/{_roleManagerConfiguration.TenantName}.onmicrosoft.com/{_roleManagerConfiguration.Policy}/oauth2/v2.0/token";

				AccessTokenRequest accessTokenRequest = new()
				{
					ClientId = _roleManagerConfiguration.ClientId,
					ClientSecret = _roleManagerConfiguration.ClientSecret,
					Scope = _roleManagerConfiguration.Scope,
					GrantType = _roleManagerConfiguration.GrantType
				};
				AccessTokenResponse accessToken = await _caller.FetchAccessToken(accessTokenRequest, accessTokenUrl);
				GetUserServiceRequest userServiceRequest = new GetUserServiceRequest()
				{
					FiscalCode = "GDASDV00A01H501J",
					ServiceId = "2ee79bc6-a8bc-4529-a1b0-9f52ff2f25ff"
				};
				UserService userService = await _caller.FetchUserService(userServiceRequest,accessToken.AccessToken);
				csrRequest.UserService = userService;

				X509Certificate2 result = await _keyVaultCertProvider.CreateCsrCertificateAndSignAsync(csrRequest, publicKey, issuerCAName);


				string pkcs7 = EncodeCertificatesAsPkcs7(new[] { result });

				SignResponse signResponse = new()
				{
					Csr = csrRequest,
					Pkcs7Result = pkcs7,
					PfxResult = EncodeCertificateAsPkcs12(result),
					X509Certificate2 = result
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

		[HttpGet]
		public async Task<IActionResult> DownloadPfx(string name)
		{
			X509Certificate2 certificate = (await GetCertificatesByNameAsync(name)).FirstOrDefault();
			if (certificate != null)
			{
				byte[] export = certificate.Export(X509ContentType.Pkcs12);
				return File(export, "application/x-pkcs12", $"{name}.pfx");
			}
			return BadRequest();
		}
	}
}
