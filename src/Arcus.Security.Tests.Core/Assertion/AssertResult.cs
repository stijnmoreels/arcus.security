using System;
using System.Collections.Generic;
using System.Linq;
using Bogus;
using Xunit;

namespace Arcus.Security.Tests.Core.Assertion
{
    public class Secret : IEquatable<Secret>
    {
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="Secret"/> class.
        /// </summary>
        public Secret(string name, string value, string version = null)
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

        public static Secret Generate(
            Func<string, string> mapSecretName = null)
        {
            string secretName = $"name-{Bogus.Random.Guid()}";
            return new Secret(
                mapSecretName is null ? secretName : mapSecretName(secretName),
                $"value-{Bogus.Random.Guid()}");
        }

        public static implicit operator KeyValuePair<string, string>(Secret secret)
        {
            return new KeyValuePair<string, string>(secret.Name, secret.Value);
        }

        public bool Equals(Secret other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return Name == other.Name && Value == other.Value && Version == other.Version;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
            {
                return false;
            }

            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (obj.GetType() != GetType())
            {
                return false;
            }

            return Equals((Secret) obj);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Name, Value, Version);
        }
    }

    public static class AssertResult
    {
        public static Secret Success(SecretResult result)
        {
            Assert.True(result.IsSuccess, $"secret result should represent a successful operation, but wasn't: {Environment.NewLine}{result}");
            return new Secret(result);
        }

        public static Secret[] Success(SecretsResult result)
        {
            Assert.True(result.IsSuccess, $"secrets result should represent a successful operation, but wasn't: {Environment.NewLine}{result}");
            return result.Select(r => new Secret(r)).ToArray();
        }

        public static void Failure(SecretResult result, params string[] errorParts)
        {
            Assert.False(result.IsSuccess, $"secret result should represent a failed operation, but wasn't: {Environment.NewLine}{result}");
            Assert.All(errorParts, part => Assert.Contains(part, result.FailureMessage));
        }
    }
}
