using System;
using Microsoft.Extensions.Configuration.Json;

namespace Arcus.Security.Providers.UserSecrets
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides user secrets.
    /// </summary>
    public class UserSecretsSecretProvider : DefaultSecretProvider
    {
        private readonly JsonConfigurationProvider _jsonProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProvider"/> class.
        /// </summary>
        internal UserSecretsSecretProvider(JsonConfigurationProvider jsonProvider, SecretProviderOptions options) : base(options)
        {
            _jsonProvider = jsonProvider ?? throw new ArgumentNullException(nameof(jsonProvider));
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            return _jsonProvider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.Failure($"No secret found '{secretName}' in user secrets at '{_jsonProvider.Source.Path}'");
        }
    }
}
