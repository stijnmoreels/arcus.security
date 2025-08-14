using System;
using System.Collections.Generic;
using System.Linq;
using Arcus.Security.Tests.Core.Assertion;
using Bogus;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    public class InMemorySecretProvider : ISecretProvider
    {
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        public InMemorySecretProvider(Dictionary<string, string> secrets)
        {
            Secrets = secrets;
        }

        public Dictionary<string, string> Secrets { get; }

        public Secret GetAnySecret()
        {
            (string key, string value) = Bogus.PickRandom(Secrets.AsEnumerable());
            return new Secret(key, value, version: null);
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        public SecretResult GetSecret(string secretName)
        {
            return Secrets.TryGetValue(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.Failure($"No in-memory secret found for '{secretName}'");
        }

        /// <summary>
        /// Stores a secret in-memory.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName" /> is blank.</exception>
        public Secret RegenerateSecret(Secret secret, string newValue = null)
        {
            ArgumentNullException.ThrowIfNull(secret);
            Secrets[secret.Name] = newValue = $"new-value-{Bogus.Random.Guid()}";
            return new Secret(secret.Name, newValue, secret.Version);
        }
    }

    public static class InMemorySecretProviderExtensions
    {
        /// <summary>
        /// Adds the in-memory secret provider to the secret store builder.
        /// </summary>
        /// <param name="builder">The secret store builder.</param>
        /// <param name="configureOptions">The action to configure the options for the in-memory secret provider.</param>
        public static SecretStoreBuilder AddInMemory(
            this SecretStoreBuilder builder,
            Dictionary<string, string> secrets,
            Action<SecretProviderOptions> configureOptions = null)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider(new InMemorySecretProvider(secrets), configureOptions);
        }
    }
}
