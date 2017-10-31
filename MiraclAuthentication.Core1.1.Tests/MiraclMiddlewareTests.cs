using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Miracl;
using NUnit.Framework;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace MiraclAuthenticationTests
{
    [TestFixture]
    public class MiraclMiddlewareTests
    {
        [Test]
        public void Test_MiraclMiddleware_NoNext()
        {
            Assert.That(() => new MiraclMiddleware(null, null, null, null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("next"));
        }

        [Test]
        public void Test_MiraclMiddleware_NoOptions()
        {
            RequestDelegate dummyRD = (HttpContext c) => { return new Task(() => { }); };
            Assert.That(() => new MiraclMiddleware(dummyRD, null, null, null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("options"));
        }

        [Test]
        public void Test_MiraclMiddleware_NoLogger()
        {
            RequestDelegate dummyRD = (HttpContext c) => { return new Task(() => { }); };
            MiraclOptions options = new MiraclOptions();
            Assert.That(() => new MiraclMiddleware(dummyRD, Options.Create(options), null, null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("loggerFactory"));
        }

        [Test]
        public void Test_MiraclMiddleware_NoEncoder()
        {
            RequestDelegate dummyRD = (HttpContext c) => { return new Task(() => { }); };
            MiraclOptions options = new MiraclOptions();
            ILoggerFactory logger = new LoggerFactory();
            Assert.That(() => new MiraclMiddleware(dummyRD, Options.Create(options), logger, null),
                Throws.TypeOf<ArgumentNullException>().And.Property("ParamName").EqualTo("encoder"));
        }

        [Test]
        public void Test_MiraclMiddleware()
        {
            RequestDelegate dummyRD = (HttpContext c) => { return new Task(() => { }); };
            MiraclOptions options = new MiraclOptions();
            ILoggerFactory logger = new LoggerFactory();
            UrlEncoder encoder = UrlEncoder.Default;
            Assert.That(new MiraclMiddleware(dummyRD, Options.Create(options), logger, encoder), Is.Not.Null);
        }

    }
}
