using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MiraclAuthenticationApp.Controllers
{
    public class loginController : Controller
    {
        public async Task<IActionResult> Index()
        {
            if (Request.Query != null && !string.IsNullOrEmpty(Request.Query["code"]) && !string.IsNullOrEmpty(Request.Query["state"]))
            {
                var properties = await HomeController.Client.ValidateAuthorization(Request.Query);
                ClaimsPrincipal user;
                if (properties != null)
                {
                    user = await HomeController.Client.GetIdentity();
                    await Request.HttpContext.Authentication.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
                }

                var idToken = properties.GetTokenValue(OpenIdConnectParameterNames.IdToken);
                if (!string.IsNullOrEmpty(idToken))
                {
                    ViewBag.IdentityTokenParsed = ParseJwt(idToken);
                }
                var accessToken = properties.GetTokenValue(OpenIdConnectParameterNames.AccessToken);
                if (!string.IsNullOrEmpty(accessToken))
                {
                    ViewBag.AccessTokenParsed = ParseJwt(accessToken);
                }
                var refreshToken = properties.GetTokenValue(OpenIdConnectParameterNames.RefreshToken);
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    ViewBag.RefreshTokenParsed = ParseJwt(refreshToken);
                }
                var expiresAt = properties.GetTokenValue(Miracl.Constants.ExpiresAt);
                if (!string.IsNullOrEmpty(expiresAt))
                {
                    ViewBag.ExpiresAt = expiresAt;
                }
            }
            else if (!User.Identity.IsAuthenticated)
            {
                //ErrorViewModel model = new ErrorViewModel() { RequestId = Request.QueryString.Value };
                //return View("Error", model);
                return View("Error");
            }

            ViewBag.Client = HomeController.Client;
            return View();
        }

        private string ParseJwt(string token)
        {
            if (!token.Contains("."))
            {
                return token;
            }

            var parts = token.Split('.');
            var part = Encoding.UTF8.GetString(Decode(parts[1]));

            var jwt = JObject.Parse(part);
            return jwt.ToString();
        }

        public static byte[] Decode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding

            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }

            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
}
