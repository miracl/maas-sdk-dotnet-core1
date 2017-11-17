using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Text.Encodings.Web;

namespace Miracl
{
    /// <summary>
    /// ASP.NET Core middleware for obtaining identities from Miracl platfrom using OpenIdConnect protocol.
    /// </summary>
    /// <seealso cref="Microsoft.AspNetCore.Authentication.AuthenticationMiddleware{Miracl.MiraclOptions}" />
    public class MiraclMiddleware : AuthenticationMiddleware<MiraclOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MiraclMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next middleware in the middleware pipeline to invoke.</param>
        /// <param name="options">The <see cref="MiraclOptions"/> for authentication.</param>
        /// <param name="loggerFactory">Factory for creating a <see cref="ILogger"/>.</param>
        /// <param name="encoder">The encoder.</param>
        /// <exception cref="ArgumentNullException">
        /// next
        /// or
        /// options
        /// or
        /// loggerFactory
        /// or
        /// encoder
        /// </exception>
        public MiraclMiddleware(
            RequestDelegate next,
            IOptions<MiraclOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder) 
            : base(next, options, loggerFactory, encoder)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            if (encoder == null)
            {
                throw new ArgumentNullException(nameof(encoder));
            }
            
            Options = options.Value;
            new MiraclPostConfigureOptions(null).PostConfigure(Constants.AuthenticationScheme, Options);
        }
        
        /// <summary>
        /// Provides the <see cref="AuthenticationHandler{T}"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler{T}"/> configured with the <see cref="MiraclOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<MiraclOptions> CreateHandler()
        {
            return new MiraclHandler(Options);
        }
    }
}
