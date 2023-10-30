using KeyVaultCa.Core.Models;

namespace KeyVaultCA.Web.Models
{
	public class SignResponse
	{
		public CertificateSigningRequest Csr {  get; set; }
		public string Result { get; set; }
	}
}
