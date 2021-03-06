using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("MiraclAuthentication.Core1.1.Tests")]

namespace Miracl
{
    /// <summary>
    /// Default values used for the Miracl Authentication
    /// </summary>
    public class Constants
    {
        public const string AuthenticationScheme = "MIRACL";
        public const string DisplayName = "Miracl";
        public const string ExpiresAt = "expires_at";
        internal const string CallbackString = "/login";
        internal const string DvsVerifyString = "/dvs/verify";
        internal const string DvsPublicKeyString = "/dvs/jwks";
        internal const string ServerBaseAddress = "https://api.mpin.io";        
        internal const string DiscoveryPath = "/.well-known/openid-configuration";
        internal const string State = "state";
        internal const string Nonce = "nonce";
        internal const string Code = "code";
        internal const string CorrelationProperty = ".xsrf";
        internal const string Error = "error";
        internal const string RefreshToken = "refresh_token";
        internal const string AccessToken = "access_token";
        internal const string Scope = "openid profile email";
        internal const string ActivateEndpoint = "/activate/user";
        internal const string ActivateInitiateEndpoint = "/activate/initiate";
        internal const string UserIdClaim = "sub";
        internal const string EmailClaim = "email";
        internal const string NonceProperty = "N";
    }
}
