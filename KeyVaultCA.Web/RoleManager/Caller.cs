using KeyVaultCA.Web.Models;
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
#warning Poi questi valori andranno gestiti meglio
		private const string TenantName = "testb2c01siag";
		private const string Policy = "B2C_1A_SIGNUP_SIGNIN_SPID";

		private const string GrantType = "client_credentials";
		private const string ClientId = "f4dd05ff-f3ab-42c4-b244-a58b6220879c";
		private const string ClientSecret = "duS8Q~tm1QBvUI4O9gr0W2TGbjwDBrKfBB4rFbqI";
		private const string Scope = "https://testb2c01siag.onmicrosoft.com/b5525739-b4fa-402d-bc0c-d0c7e6888ab2/.default";

		private string GetAccessTokenUrl = $"https://{TenantName}.b2clogin.com/{TenantName}.onmicrosoft.com/{Policy}/oauth2/v2.0/token";
		public async Task<string> FetchAccessToken()
		{
			string token = string.Empty;

			AccessTokenRequest request = new()
			{
				ClientId = ClientId,
				ClientSecret = ClientSecret,
				Scope = Scope,
				GrantType = GrantType
			};
			using (HttpClient client = new())
			{
				HttpResponseMessage response = await client.PostAsJsonAsync(GetAccessTokenUrl, request);

				if (response.IsSuccessStatusCode)
				{
					string fullResponse = await response.Content.ReadAsStringAsync();
					AccessTokenResponse tokenResponse = JsonSerializer.Deserialize<AccessTokenResponse>(fullResponse);
					token = tokenResponse.AccessToken;
				}
			}

			return token;
		}

		public async Task<UserService> GetUserServiceForService(GetUserServiceRequest request, string token)
		{
			HttpRequestMessage httpRequest = new HttpRequestMessage()
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
					return JsonSerializer.Deserialize<UserService>(responseString);

				}
			}
			return null;
		}
	}
}
