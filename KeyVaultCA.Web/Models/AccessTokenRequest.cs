using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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

		public IEnumerable<KeyValuePair<string, string>> GetAsKeyValuePairs()
		{
			//return this.GetType()
			//	.GetProperties(BindingFlags.Instance | BindingFlags.Public)
			//		.ToDictionary(prop => prop.Name, prop => (string)prop.GetValue(this, null));

			return new Dictionary<string,string>()
			{
				{ "grant_type", this.GrantType },
				{ "client_id", this.ClientId },
				{ "client_secret", this.ClientSecret },
				{ "scope", this.Scope }
			};
		}
	}
}
