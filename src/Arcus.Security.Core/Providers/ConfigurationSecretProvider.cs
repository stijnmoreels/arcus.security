using System;
using Microsoft.Extensions.Configuration;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the <see cref="IConfiguration"/>. It is recommended to only use this for development purposes.
    /// </summary>
    public class ConfigurationSecretProvider : DefaultSecretProvider
    {
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationSecretProvider"/> class.
        /// </summary>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="options">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configuration"/> is <c>null</c>.</exception>
        public ConfigurationSecretProvider(IConfiguration configuration, SecretProviderOptions options) : base(options)
        {
            ArgumentNullException.ThrowIfNull(configuration);
            _configuration = configuration;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            string secretValue = _configuration[secretName];
            return secretValue is null
                ? SecretResult.Failure($"No secret found in application configuration for '{secretName}'")
                : SecretResult.Success(secretName, secretValue);
        }
    }
}
