using KeyVaultCa.Core.Models;
using KeyVaultCA.Web.Models;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Numerics;
using System.Text.Json;
using System.Threading.Tasks;

namespace KeyVaultCA.Web.RoleManager
{
	public class Caller
	{
		private readonly ILogger _logger;

        public Caller()
        {
			ILoggerFactory loggerFactory = new LoggerFactory();
            _logger = loggerFactory.CreateLogger<Caller>();
        }
        public async Task<AccessTokenResponse> FetchAccessToken(AccessTokenRequest request, string url)
		{
			AccessTokenResponse accessTokenResponse = null;

			using (HttpClient client = new())
			{
				using (FormUrlEncodedContent content = new(request.GetAsKeyValuePairs()))
				{
					content.Headers.Clear();
					content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

					HttpResponseMessage response = await client.PostAsync(url, content);

					if (response.IsSuccessStatusCode)
					{
						string fullResponse = await response.Content.ReadAsStringAsync();
						accessTokenResponse = JsonSerializer.Deserialize<AccessTokenResponse>(fullResponse);
						_logger.LogInformation("access token fetched: {0}", accessTokenResponse.AccessToken);
					}
					else
					{
						_logger.LogError("call to {0} in error: {1}", url, response.ReasonPhrase);
					}
				}
			}
			return accessTokenResponse;
		}

		public async Task<UserService> FetchUserService(GetUserServiceRequest request, string token)
		{
			UserService userService = null;
			HttpRequestMessage httpRequest = new()
			{
				RequestUri = new Uri("https://app-rolemanager-api-siag-test.azurewebsites.net/GetUserServiceForService"),
				Method = HttpMethod.Post,
				Content = JsonContent.Create(request)
			};

			httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

			using (HttpClient client = new())
			{
				HttpResponseMessage response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead);
				if (response.StatusCode == System.Net.HttpStatusCode.OK)
				{
					string responseString = await response.Content.ReadAsStringAsync();
					userService = JsonSerializer.Deserialize<UserService>(responseString);
				}
			}

			return userService;
		}
	}
}
