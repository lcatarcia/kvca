using Azure;
using Azure.Security.KeyVault.Certificates;
using KeyVaultCa.Core;
using KeyVaultCa.Core.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Swashbuckle.AspNetCore.Annotations;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultCA.Web.Controllers
{
    [ApiController]
    public class EstController : ControllerBase
    {
        private const string PKCS7_MIME_TYPE = "application/pkcs7-mime";
        private const string PKCS10_MIME_TYPE = "application/pkcs10";

        private readonly ILogger _logger;
        private readonly IKeyVaultCertificateProvider _keyVaultCertProvider;
        private readonly EstConfiguration _configuration;

        public EstController(ILogger<EstController> logger, IKeyVaultCertificateProvider keyVaultCertProvider, EstConfiguration configuration)
        {
            _logger = logger;
            _keyVaultCertProvider = keyVaultCertProvider;
            _configuration = configuration;
        }

        [HttpGet]
        //[Authorize]
        //[Route(".well-known/est/cacerts")]
        //[Route("ca/.well-known/est/cacerts")]
        [Route("getCACertificates")]
        [SwaggerOperation(Summary ="Returns a list of CA Certificates")]
        public async Task<IActionResult> GetCACertsAsync()
        {
            _logger.LogDebug("Call 'CA certs' endpoint.");
            IList<X509Certificate2> caCerts = await _keyVaultCertProvider.GetPublicCertificatesByName(new[] { _configuration.IssuingCA });
            string pkcs7 = EncodeCertificatesAsPkcs7(caCerts.ToArray());

            return Content(pkcs7, PKCS7_MIME_TYPE);
        }

        

        [HttpGet]
        [Route("getPublicKey")]
        [SwaggerOperation(Summary = "Retrieves the public key for the CA certificate")]
        public async Task<IActionResult> GetPublicKey()
        {
            List<PublicKey> publicKeys = await GetPublicKeyList();
            if (publicKeys.Any())
                return Ok(publicKeys);
            return NoContent();
        }

        [HttpGet("getCertificateByName")]
        [SwaggerOperation(Summary = "Returns a certificate content by its name")]
        public async Task<IActionResult> GetCertificateByName(string name)
        {
            _logger.LogDebug("Call 'Get Certificate by name' endpoint.");
            IList<X509Certificate2> certs = await GetCertificatesByNameAsync(name);
            string pkcs7 = EncodeCertificatesAsPkcs7(certs.ToArray());

            return Content(pkcs7, PKCS7_MIME_TYPE);
        }

        [HttpPost]
        //[Authorize]
        //[Route(".well-known/est/simpleenroll")]
        //[Route("ca/.well-known/est/simpleenroll")]
        [Route("signPKCS10Content")]
        [Consumes(PKCS10_MIME_TYPE)]
        [SwaggerOperation(Summary = "Executes a sign operation on a Pkcs10 content")]
        public async Task<IActionResult> EnrollAsync()
        {
            _logger.LogDebug("Call 'Simple Enroll' endpoint.");

            string cleanedUpBody = await GetAsn1StructureFromBody();

            _logger.LogDebug("Request body is: {body}.", cleanedUpBody);

            bool caCert = Request.Path.StartsWithSegments("/ca");

            _logger.LogInformation("Is a CA certificate: {flag}.", caCert);

            X509Certificate2 cert = await _keyVaultCertProvider.SignRequestAsync(
                Convert.FromBase64String(cleanedUpBody),
                _configuration.IssuingCA,
                _configuration.CertValidityInDays,
                null,
                caCert);

            string pkcs7 = EncodeCertificatesAsPkcs7(new[] { cert });
            return Content(pkcs7, PKCS7_MIME_TYPE);
        }

        [HttpPost]
        [Route("createCsrCertificate")]
        [SwaggerOperation(Summary = "Creates a certificate and saves to KV, without signature")]
        [ApiExplorerSettings(IgnoreApi =true)]
        public async Task<IActionResult> CreateCsrCertificate([FromBody] CertificateSigningRequest csrRequest)
        {
            _logger.LogDebug($"Call create CSR certificate endpoint. Certificate name = {csrRequest.CertificateName}");
            try
            {
                PublicKey publicKey = (await GetPublicKeyList())?.FirstOrDefault() ?? null;
                byte[] result = await _keyVaultCertProvider.CreateCsrCertificateAsync(csrRequest, publicKey);

                Response<X509Certificate2> certificate = await _keyVaultCertProvider.DownloadCertificateAsync(csrRequest.CertificateName);

                string pkcs7 = EncodeCertificatesAsPkcs7(new[] { certificate.Value });
                return Ok(pkcs7);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetPublicKey error");
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("createCsrCertificateAndSign")]
        [SwaggerOperation(Summary = "Based on a set of parameters, it creates a certificate and returns the certificate signed by CA")]
        public async Task<IActionResult> CreateCsrCertificateAndSign([FromBody] CertificateSigningRequest csrRequest)
        {
            _logger.LogDebug($"Call create CSR certificate and sign endpoint. Certificate name = {csrRequest.CertificateName}");
            try
            {
                string issuerCAName = _configuration.IssuingCA;
                PublicKey publicKey = (await GetPublicKeyList())?.FirstOrDefault() ?? null;
                X509Certificate2 result = await _keyVaultCertProvider.CreateCsrCertificateAndSignAsync(csrRequest, publicKey, issuerCAName);

                string pkcs7 = EncodeCertificatesAsPkcs7(new[] { result });
                return Ok(pkcs7);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetPublicKey error");
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("createCACertificate")]
        [SwaggerOperation(Summary = "Creates a CA certificate")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> CreateCACertificate([FromBody] CertificateSigningRequest csrRequest)
        {
            _logger.LogDebug($"Call create CA certificate endpoint. Certificate name = {csrRequest.CertificateName}");
            try
            {
                string subject = $"C={csrRequest.Country}, ST={csrRequest.State}, L={csrRequest.Locality}, O={csrRequest.Organization}, OU={csrRequest.OrganizationUnit}, CN={csrRequest.CommonName}";
                await _keyVaultCertProvider.CreateCACertificateAsync(csrRequest.CertificateName, subject, 1);

                Response<X509Certificate2> certificate = await _keyVaultCertProvider.DownloadCertificateAsync(csrRequest.CertificateName);

                string pkcs7 = EncodeCertificatesAsPkcs7(new[] { certificate.Value });
                return Ok(pkcs7);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "createCACertificate error");
                return BadRequest(ex.Message);
            }
        }



        //[HttpGet("getSignedCertificateByName")]
        //public async Task<IActionResult> GetSignedCertificateByName(string name)
        //{
        //    _logger.LogDebug("Call 'Get Signed Certificate by name' endpoint.");
        //    IList<X509Certificate2> certs = await GetCertificatesByNameAsync(name);

        //    byte[] rawData = certs.FirstOrDefault().RawData;

        //    X509Certificate2 signedCert = await _keyVaultCertProvider.SignRequestAsync(
        //        rawData, _configuration.IssuingCA, _configuration.CertValidityInDays, false);

        //    //string pkcs7 = EncodeCertificatesAsPkcs7(certs.ToArray());
        //    //return Content(pkcs7, PKCS7_MIME_TYPE);

        //    return Ok(signedCert);
        //}

        //[HttpPost("testCsr")]
        //public async Task<IActionResult> TestCsr([FromBody] CertificateSigningRequest csrRequest)
        //{
        //    //Both ECDSA and RSA included here, though ECDSA is probably better.
        //    using (ECDsa privateClientEcdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        //    //using(RSA privateClientRsaKey = RSA.Create(2048))
        //    {
        //        //A client creates a certificate signing request.
        //        CertificateRequest request = new(
        //            new X500DistinguishedName(
        //                $"CN={csrRequest.CommonName}," +
        //                $" O={csrRequest.Organization}," +
        //                $" OU={csrRequest.OrganizationUnit}," +
        //                $" L={csrRequest.Locality}," +
        //                $" ST={csrRequest.State}," +
        //                $" C={csrRequest.Country}," +
        //                $" E={csrRequest.Email}"),
        //            privateClientEcdsaKey,
        //            HashAlgorithmName.SHA256);

        //        SubjectAlternativeNameBuilder sanBuilder = new();
        //        sanBuilder.AddDnsName($"{csrRequest.CommonName}");
        //        request.CertificateExtensions.Add(sanBuilder.Build());

        //        //Not a CA, a server certificate.
        //        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        //        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        //        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") }, false));

        //        byte[] derEncodedCsr = request.CreateSigningRequest();
        //        StringBuilder csrSb = new();
        //        csrSb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        //        csrSb.AppendLine(Convert.ToBase64String(derEncodedCsr));
        //        csrSb.AppendLine("-----END CERTIFICATE REQUEST-----");

        //        //Thus far OK, this csr seems to be working when using an online checker.
        //        string csr = csrSb.ToString();

        //        return Ok(csr);
        //    }
        //}

        private async Task<List<PublicKey>> GetPublicKeyList()
        {
            List<PublicKey> publicKeys = new();
            try
            {
                IList<X509Certificate2> caCerts = await _keyVaultCertProvider.GetPublicCertificatesByName(new[] { _configuration.IssuingCA });

                foreach (X509Certificate2 cert in caCerts)
                {
                    publicKeys.Add(cert.PublicKey);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetPublicKeys error");
            }
            return publicKeys;
        }

        private async Task<IList<X509Certificate2>> GetCertificatesByNameAsync(string name)
            => await _keyVaultCertProvider.GetPublicCertificatesByName(new[] { name });

        private string EncodeCertificatesAsPkcs7(X509Certificate2[] certs)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection(certs);
            byte[] data = collection.Export(X509ContentType.Pkcs7);

            StringBuilder builder = new StringBuilder();
            builder.AppendLine(Convert.ToBase64String(data));

            return builder.ToString();
        }

        private async Task<string> GetAsn1StructureFromBody()
        {
            using StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8);
            string body = await reader.ReadToEndAsync();

            // Need to handle different types of Line Breaks
            string[] tokens = body.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            string token = tokens.Length > 1 ? string.Join(string.Empty, tokens) : tokens.FirstOrDefault();

            _logger.LogDebug("Returning token: {token} ", token);

            return token;
        }

        private async Task<string> GetAsn1StructureFromBody(string body)
        {
            // Need to handle different types of Line Breaks
            string[] tokens = body.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            string token = tokens.Length > 1 ? string.Join(string.Empty, tokens) : tokens.FirstOrDefault();

            _logger.LogDebug("Returning token: {token} ", token);

            return token;
        }
    }
}
