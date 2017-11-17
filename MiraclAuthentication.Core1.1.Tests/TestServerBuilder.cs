using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Miracl;
using System;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    internal class TestServerBuilder
    {
        public static readonly string DefaultAuthority = @"https://api.dev.miracl.net";
        public static readonly string TestHost = @"https://example.com";
        public static readonly string Challenge = "/challenge";
        public static readonly string ChallengeWithProperties = "/challengeWithProperties";

        public static TestServer CreateServer(MiraclOptions options)
        {
            return CreateServer(options, handler: null, properties: null);
        }

        public static TestServer CreateServer(
            MiraclOptions options,
            Func<HttpContext, Task> handler,
            AuthenticationProperties properties)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseCookieAuthentication(new CookieAuthenticationOptions());

                    app.UseMiraclAuthentication(options);

                    app.Use(async (context, next) =>
                    {
                        var req = context.Request;
                        var res = context.Response;

                        if (req.Path == new PathString(Challenge))
                        {
                            await context.Authentication.ChallengeAsync(Constants.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString(ChallengeWithProperties))
                        {
                            await context.Authentication.ChallengeAsync(Constants.AuthenticationScheme, properties);
                        }
                        else if (handler != null)
                        {
                            await handler(context);
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddAuthentication();
                });

            return new TestServer(builder);
        }
    }
}
