using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.CommandLine;

namespace Arcus.Security.Providers.CommandLine
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> implementation that provides the command line arguments as secrets to the secret store.
    /// </summary>
    public class CommandLineSecretProvider : DefaultSecretProvider
    {
        private readonly CommandLineConfigurationProvider _configurationProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandLineSecretProvider"/> class.
        /// </summary>
        /// <param name="configurationProvider">The command line <see cref="IConfigurationProvider"/> to load the command arguments as secrets.</param>
        /// <param name="options"></param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configurationProvider"/> is <c>null</c>.</exception>
        public CommandLineSecretProvider(CommandLineConfigurationProvider configurationProvider, SecretProviderOptions options) : base(options)
        {
            _configurationProvider = configurationProvider;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            return _configurationProvider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.Failure($"No '{secretName}' secret found in command line arguments");
        }
    }
}
