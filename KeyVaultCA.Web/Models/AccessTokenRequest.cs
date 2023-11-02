using System.Text.Json.Serialization;

namespace KeyVaultCA.Web.Models
{
	public class AccessTokenRequest
	{
		[JsonPropertyName("grant_type")]
		public string GrantType { get; set; }

		[JsonPropertyName("client_id")]
		public string ClientId { get; set; }

		[JsonPropertyName("client_secret")]
		public string ClientSecret { get; set; }

		[JsonPropertyName("scope")]
		public string Scope { get; set; }
	}
}
