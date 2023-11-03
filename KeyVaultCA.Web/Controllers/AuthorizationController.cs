using Azure.Core;
using KeyVaultCa.Core.Models;
using KeyVaultCA.Web.Models;
using KeyVaultCA.Web.RoleManager;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Ocsp;
using Polly;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

namespace KeyVaultCA.Web.Controllers
{
	[ApiController]
	public class AuthorizationController : ControllerBase
	{
		private readonly ILogger _logger;
		private readonly RoleManagerConfiguration _roleManagerConfig;
		private readonly Caller _caller;

		public AuthorizationController(
			ILogger<AuthorizationController> logger, 
			RoleManagerConfiguration roleManagerConfig,
			Caller caller)
		{
			_logger = logger;
			_roleManagerConfig = roleManagerConfig;
			_caller = caller;	
		}


		[HttpPost("GetAccessToken")]
		public async Task<IActionResult> GetAccessToken()
		{
			try
			{
				string accessTokenUrl = $"https://{_roleManagerConfig.TenantName}.b2clogin.com/{_roleManagerConfig.TenantName}.onmicrosoft.com/{_roleManagerConfig.Policy}/oauth2/v2.0/token";

				AccessTokenRequest request = new()
				{
					ClientId = _roleManagerConfig.ClientId,
					ClientSecret = _roleManagerConfig.ClientSecret,
					Scope = _roleManagerConfig.Scope,
					GrantType = _roleManagerConfig.GrantType
				};

				AccessTokenResponse accessToken = await _caller.FetchAccessToken(request, accessTokenUrl);
				if (accessToken != null)
					return Ok(accessToken.AccessToken);
				return BadRequest();
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error in GetAccessToken operation");
				return BadRequest();
			}
		}


		[HttpPost("GetUserService")]
		public async Task<IActionResult> GetUserService(GetUserServiceRequest request)
		{
			string accessTokenUrl = $"https://{_roleManagerConfig.TenantName}.b2clogin.com/{_roleManagerConfig.TenantName}.onmicrosoft.com/{_roleManagerConfig.Policy}/oauth2/v2.0/token";

			AccessTokenRequest accessTokenRequest = new()
			{
				ClientId = _roleManagerConfig.ClientId,
				ClientSecret = _roleManagerConfig.ClientSecret,
				Scope = _roleManagerConfig.Scope,
				GrantType = _roleManagerConfig.GrantType
			};
			AccessTokenResponse accessToken = await _caller.FetchAccessToken(accessTokenRequest, accessTokenUrl);
			if (accessToken != null)
			{
				UserService userService = await _caller.FetchUserService(request, accessToken.AccessToken);
				if (userService != null)
					return Ok(userService);
			}
			return Unauthorized();
		}
	}
}
