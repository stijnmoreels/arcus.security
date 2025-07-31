using System.Collections.Generic;
using Bogus;
using Xunit;

namespace Arcus.Security.Tests.Core.Assertion
{
    public class Secret
    {
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        public Secret(string name, string value, string version)
        {
            Name = name;
            Value = value;
            Version = version;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        public Secret(SecretResult result)
        {
            Name = result.Name;
            Value = result.Value;
            Version = result.Version;
        }

        public string Name { get; internal set; }
        public string Value { get; internal set; }
        public string Version { get; internal set; }

        public static Secret Generate()
        {
            return new Secret(
                $"name-{Bogus.Random.Guid()}",
                $"value-{Bogus.Random.Guid()}",
                Bogus.System.Version().ToString().OrNull(Bogus));
        }

        public static implicit operator KeyValuePair<string, string>(Secret secret)
        {
            return new KeyValuePair<string, string>(secret.Name, secret.Value);
        }
    }

    public static class AssertResult
    {
        public static Secret Success(SecretResult result)
        {
            Assert.True(result.IsSuccess, $"secret result should represent a successful operation, but wasn't: {result}");
            return new Secret(result);
        }

        public static void Failure(SecretResult result, params string[] errorParts)
        {
            Assert.False(result.IsSuccess, $"secret result should represent a failed operation, but wasn't: {result}");
            Assert.All(errorParts, part => Assert.Contains(part, result.FailureMessage));
        }
    }
}
