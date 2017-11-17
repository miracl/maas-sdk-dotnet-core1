using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Miracl
{
    /// <summary>
    /// A per-request authentication handler for the MiraclAuthenticationMiddleware.
    /// </summary>
    public class MiraclHandler : RemoteAuthenticationHandler<MiraclOptions>
    {
        #region Fields
        static MiraclClient client;
        #endregion

        #region C'tor
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclHandler"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="encoder">The encoder.</param>
        /// <param name="clock">The clock.</param>
        public MiraclHandler(MiraclOptions options) : base()
        {
            if (client == null)
            {
                client = new MiraclClient();
            }

            options.GetClaimsFromUserInfoEndpoint = true;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.TokenValidationParameters = options.TokenValidationParameters ?? new TokenValidationParameters { ValidateIssuer = true };
            options.SaveTokens = true;
            client.Options = options;
        }
        #endregion

        #region overrides

        /// <summary>
        /// Responds to a 401 challenge. If an authentication scheme is in a question,
        /// it uses a <see cref="MiraclClient" /> object to deal with the authentication
        /// interaction as part of it's request flow.
        /// </summary>
        /// <param name="context">The context of the authentication.</param>
        /// <returns>
        /// True if no other handlers should be called
        /// </returns>
        /// <exception cref="ArgumentNullException">context</exception>
        /// <exception cref="ArgumentException">MiraclClient should be initialized</exception>
        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = new AuthenticationProperties(context.Properties);

            if (Options.AuthenticationMethod == OpenIdConnectRedirectBehavior.RedirectGet)
            {
                if (Request.QueryString == null || !Request.QueryString.Value.Contains("code") || !Request.QueryString.Value.Contains("state"))
                {
                    if (string.IsNullOrEmpty(properties.RedirectUri))
                    {
                        properties.RedirectUri = CurrentUri;
                    }

                    string url = Request.Scheme + "://" + Request.Host.Value;
                    GenerateCorrelationId(properties);
                    string authUrl = await client.GetAuthorizationRequestUrlAsync(url, null, properties);
                    WriteNonceCookie();
                    Response.Redirect(authUrl);
                }
            }

            return true;
        }

        /// <summary>
        /// Authenticates the user identity with the identity provider.
        /// The method process the request on the endpoint defined by the CallbackPath.
        /// </summary>
        /// <returns>A <see cref="HandleRequestResult"/>.</returns>
        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync()
        {
            var result = await ShouldReturnResult();
            if (result != null)
            {
                return result;
            }

            // Authorization code flow
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
               Request.Path == client.Options.CallbackPath &&
               Request.QueryString != null && Request.QueryString.Value.Contains("code") && Request.QueryString.Value.Contains("state"))
            {
                ClaimsPrincipal user;
                AuthenticationProperties properties;
                try
                {
                    properties = await client.ValidateAuthorization(Request.Query);
                    if (properties == null)
                    {
                        if (Options.SkipUnrecognizedRequests)
                        {
                            return AuthenticateResult.Skip();
                        }
                        return AuthenticateResult.Fail("Validation failed!");
                    }

                    if (!ValidateCorrelationId(properties))
                    {
                        return AuthenticateResult.Fail("Correlation failed.");
                    }

                    ReadNonceCookie(client.Nonce);
                    user = await client.GetIdentity(Constants.AuthenticationScheme);
                }
                catch (ArgumentException ae)
                {
                    return AuthenticateResult.Fail(ae);
                }

                return AuthenticateResult.Success(new AuthenticationTicket(user, properties, Constants.AuthenticationScheme));
            }

            return AuthenticateResult.Skip();
        }
        #endregion

        #region Methods        

        private void WriteNonceCookie()
        {
            if (Options.ProtocolValidator.RequireNonce)
            {                
                Response.Cookies.Append(
                OpenIdConnectDefaults.CookieNoncePrefix + Options.StringDataFormat.Protect(client.Nonce),
                Constants.NonceProperty,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsHttps,
                    Expires = Options.SystemClock.UtcNow.Add(Options.ProtocolValidator.NonceLifetime)
                });
            }
        }

        /// <summary>
        /// Searches <see cref="HttpRequest.Cookies"/> for a matching nonce.
        /// </summary>
        /// <param name="nonce">the nonce that we are looking for.</param>
        /// <remarks>Examine <see cref="IRequestCookieCollection.Keys"/> of <see cref="HttpRequest.Cookies"/> that start with the prefix: 'OpenIdConnectAuthenticationDefaults.Nonce'.
        /// <see cref="M:ISecureDataFormat{TData}.Unprotect"/> of <see cref="OpenIdConnectOptions.StringDataFormat"/> is used to obtain the actual 'nonce'. If the nonce is found,
        /// then <see cref="M:IResponseCookies.Delete"/> of <see cref="HttpResponse.Cookies"/> is called.</remarks>
        private void ReadNonceCookie(string nonce)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                return;
            }

            foreach (var nonceKey in Request.Cookies.Keys)
            {
                if (nonceKey.StartsWith(OpenIdConnectDefaults.CookieNoncePrefix))
                {
                    try
                    {
                        var nonceDecodedValue = Options.StringDataFormat.Unprotect(nonceKey.Substring(OpenIdConnectDefaults.CookieNoncePrefix.Length, nonceKey.Length - OpenIdConnectDefaults.CookieNoncePrefix.Length));
                        if (nonceDecodedValue == nonce)
                        {
                            var cookieOptions = new CookieOptions
                            {
                                HttpOnly = true,
                                Secure = Request.IsHttps
                            };

                            Response.Cookies.Delete(nonceKey, cookieOptions);
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new ArgumentException("Unable to protect the nonce cookie: " + ex.Message);
                    }
                }
            }
        }

        /// <summary>
        /// Check if the request should be oidc validated or should continue.
        /// </summary>
        /// <returns>An <see cref="AuthenticateResult"/> if the authentication cannot contiue or nothing to 
        /// continue the authentication of the request.</returns>        
        private async Task<AuthenticateResult> ShouldReturnResult()
        {
            OpenIdConnectMessage authorizationResponse = null;
            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                authorizationResponse = new OpenIdConnectMessage(Request.Query.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));

                // response_mode=query explicit or not() and a response_type containing id_token
                // or token are not considered as a safe combination and MUST be rejected.
                // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
                if (!string.IsNullOrEmpty(authorizationResponse.IdToken) || !string.IsNullOrEmpty(authorizationResponse.AccessToken))
                {
                    if (Options.SkipUnrecognizedRequests)
                    {
                        // Not for us?
                        return AuthenticateResult.Skip();
                    }
                    return AuthenticateResult.Fail("An OpenID Connect response cannot contain an " +
                            "identity token or an access token when using response_mode=query");
                }
            }
            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small
            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
              && !string.IsNullOrEmpty(Request.ContentType)
              // May have media/type; charset=utf-8, allow partial match.
              && Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
              && Request.Body.CanRead)
            {
                var form = await Request.ReadFormAsync();
                authorizationResponse = new OpenIdConnectMessage(form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value)));
            }

            if (authorizationResponse == null)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    // Not for us?
                    return AuthenticateResult.Skip();
                }
                return AuthenticateResult.Fail("No message.");
            }

            return null;
        }
        #endregion
    }
}
