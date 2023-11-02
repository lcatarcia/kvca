using Microsoft.AspNetCore.Mvc;

namespace KeyVaultCA.Web.Controllers
{
	public class AuthorizationController : Controller
	{
		public IActionResult Index()
		{
			return View();
		}
	}
}
