using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Unit
{
    public abstract class UnitTest
    {
        protected static readonly Faker Bogus = new();

        protected UnitTest(ITestOutputHelper outputWriter)
        {
            Logger = new XunitTestLogger(outputWriter);
        }

        protected ILogger Logger { get; }
    }
}
