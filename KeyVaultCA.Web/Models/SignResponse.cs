using KeyVaultCa.Core.Models;
using System.Security.Cryptography.X509Certificates;

namespace KeyVaultCA.Web.Models
{
	public class SignResponse
	{
		public CertificateSigningRequest Csr {  get; set; }
		public string Pkcs7Result { get; set; }
		public byte[] PfxResult { get; set; }
		public X509Certificate2 X509Certificate2 { get; set; }
	}
}
