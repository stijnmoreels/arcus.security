using Arcus.Testing;
using Bogus;
using Xunit.Abstractions;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Arcus.Security.Tests.Integration
{
    public abstract class IntegrationTest
    {
        protected static readonly Faker Bogus = new();

        protected IntegrationTest(ITestOutputHelper testOutput)
        {
            Configuration = TestConfig.Create();
            Logger = new XunitTestLogger(testOutput);
        }

        protected TestConfig Configuration { get; }
        protected ILogger Logger { get; }
    }
}