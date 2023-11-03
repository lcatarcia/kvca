namespace KeyVaultCA.Web.RoleManager
{
	public class RoleManagerConfiguration
	{
		public string TenantName { get; set; }
		public string Policy { get; set; }

		public string GrantType { get; set; }
		public string ClientId { get; set; }
		public string ClientSecret { get; set; }
		public string Scope { get; set; }
	}
}
