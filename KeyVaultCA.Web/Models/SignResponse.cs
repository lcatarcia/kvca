using KeyVaultCa.Core.Models;

namespace KeyVaultCA.Web.Models
{
	public class SignResponse
	{
		public CertificateSigningRequest Csr {  get; set; }
		public string Pkcs7Result { get; set; }
		public byte[] PfxResult { get; set; }
	}
}
