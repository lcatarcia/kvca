using System;

namespace KeyVaultCa.Core.Models
{
    public class CertificateSigningRequest
    {
        public string CertificateName { get; set; } = $"SIAG{DateTime.Now:MMddhhmm}";
        public int KeySize { get; set; } = 4096;
        public string CommonName {  get; set; }
        public string SubjectAlternativeName { get; set; }
        public string Organization {  get; set; }
        public string OrganizationUnit {  get; set; }
        public string Locality {  get; set; }
        public string State {  get; set; }
        public string Country {  get; set; }
        public string Email {  get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
    }
}
