using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using System;

namespace Miracl
{
    /// <summary>
    /// Extension methods to add Miracl authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class MiraclAppBuilderExtensions
    {
        /// <summary>
        /// Adds the <see cref="MiraclMiddleware" /> middleware to the specified <see cref="IApplicationBuilder" />, which enables OpenID Connect authentication capabilities to the Miracl platform.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to add the middleware to.</param>
        /// <param name="options">A <see cref="MiraclOptions" /> that specifies options for the middleware.</param>
        /// <returns>
        /// A reference to this instance after the operation has completed.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// app
        /// or
        /// options
        /// </exception>
        public static IApplicationBuilder UseMiraclAuthentication(this IApplicationBuilder app, MiraclOptions options)
        {         
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<MiraclMiddleware>(Options.Create(options));
        }
    }
}
