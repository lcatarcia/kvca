using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace KeyVaultCa.Core.Models
{
	public class UserService
	{
		[JsonPropertyName("userObjectId")]
		public string UserObjectId { get; set; }

		[JsonPropertyName("serviceOfUsers")]
		public List<Service> ServiceOfUsers { get; set; }

		[JsonPropertyName("accessLevel")]
		public int AccessLevel { get; set; }

		[JsonPropertyName("userName")]
		public string UserName { get; set; }

		[JsonPropertyName("userSurname")]
		public string UserSurname { get; set; }
	}

	public class Service
	{
		[JsonPropertyName("id")]
		public string Id { get; set; }

		[JsonPropertyName("name")]
		public string Name { get; set; }

		[JsonPropertyName("description")]
		public string Description { get; set; }

		[JsonPropertyName("contactPerson")]
		public string ContactPerson { get; set; }

		[JsonPropertyName("contactPersonId")]
		public string ContactPersonId { get; set; }

		[JsonPropertyName("roles")]
		public List<Role> Roles { get; set; }

		[JsonPropertyName("isVisible")]
		public bool IsVisible { get; set; }
	}

	public class Role
	{
		[JsonPropertyName("id")]
		public string Id { get; set; }

		[JsonPropertyName("name")]
		public string Name { get; set; }

		[JsonPropertyName("description")]
		public string Description { get; set; }

		[JsonPropertyName("attributes")]
		public List<Attribute> Attributes { get; set; }

		[JsonPropertyName("powerLevels")]
		public List<int> PowerLevels { get; set; }
	}

	public class Attribute
	{
		[JsonPropertyName("name")]
		public string Name { get; set; }

		[JsonPropertyName("description")]
		public string Description { get; set; }
	}
}
