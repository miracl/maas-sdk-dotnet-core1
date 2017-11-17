using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Miracl;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MiraclAuthenticationApp.Controllers
{
    public class HomeController : Controller
    {
        internal static MiraclClient Client;
        public async Task<IActionResult> Index()
        {
            var url = Request.Scheme + "://" + Request.Host.Value;
            ViewBag.AuthorizationUri = await GetUrl(url);
            return View();
        }

        internal static async Task<string> GetUrl(string url)
        {
            if (Client == null)
            {
                Client = new MiraclClient(new MiraclOptions
                {
                    ClientId = Startup.Configuration["zfa:ClientId"],
                    ClientSecret = Startup.Configuration["zfa:ClientSecret"],
                    SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                    SaveTokens = true
                });
            }

            return await Client.GetAuthorizationRequestUrlAsync(url);
        }

        public IActionResult Error()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Index(string Logout)
        {
            if (Logout != null)
            {
                Client.ClearUserInfo(false);
                await Request.HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            return RedirectToAction("Index");
        }
    }
}
