namespace KeyVaultCa.Core.Models
{
    public class CreateCsrRequest
    {
        public string CertificateName {  get; set; }
        public int KeySize {  get; set; }
        public string CommonName {  get; set; }
        public string SubjectAlternativeName { get; set; }
        public string Organization {  get; set; }
        public string OrganizationUnit {  get; set; }
        public string Locality {  get; set; }
        public string State {  get; set; }
        public string Country {  get; set; }
        public string Email {  get; set; }
    }
}
