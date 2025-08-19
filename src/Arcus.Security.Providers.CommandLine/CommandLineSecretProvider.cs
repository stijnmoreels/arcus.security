using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.CommandLine;
using static Arcus.Security.SecretResult;

namespace Arcus.Security.Providers.CommandLine
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> implementation that provides the command line arguments as secrets to the secret store.
    /// </summary>
    public class CommandLineSecretProvider : ISecretProvider
    {
        private readonly CommandLineConfigurationProvider _configurationProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandLineSecretProvider"/> class.
        /// </summary>
        /// <param name="configurationProvider">The command line <see cref="IConfigurationProvider"/> to load the command arguments as secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configurationProvider"/> is <c>null</c>.</exception>
        private CommandLineSecretProvider(CommandLineConfigurationProvider configurationProvider)
        {
            _configurationProvider = configurationProvider;
        }

        internal static CommandLineSecretProvider Create(string[] arguments)
        {
            var configProvider = new CommandLineConfigurationProvider(arguments);
            configProvider.Load();

            return new CommandLineSecretProvider(configProvider);
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        public SecretResult GetSecret(string secretName)
        {
            return _configurationProvider.TryGet(secretName, out string secretValue)
                ? Success(secretName, secretValue)
                : NotFound($"No '{secretName}' secret found in command line arguments");
        }
    }
}
