using System.Text.Json.Serialization;

namespace KeyVaultCA.Web.Models
{
	public class GetUserServiceRequest
	{
		[JsonPropertyName("fiscalCode")]
		public string FiscalCode { get; set; }

		[JsonPropertyName("serviceId")]
		public string ServiceId {  get; set; }
	}
}
