using System;
using System.IO;
using Microsoft.Extensions.Configuration.KeyPerFile;
using Microsoft.Extensions.FileProviders;

namespace Arcus.Security.Providers.DockerSecrets
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider" /> that provides access to the Docker secrets mounted into the Docker container as files.
    /// </summary>
    public class DockerSecretsSecretProvider : DefaultSecretProvider
    {
        private readonly string _secretsDirectoryPath;
        private readonly KeyPerFileConfigurationProvider _provider;

        /// <summary>
        /// Initializes a new instance of the <see cref="DockerSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="secretsDirectoryPath">The directory path inside the Docker container where the secrets are located.</param>
        /// <param name="options"></param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretsDirectoryPath"/> is blank or not an absolute path.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the <paramref name="secretsDirectoryPath"/> is not found on the system.</exception>
        internal DockerSecretsSecretProvider(string secretsDirectoryPath, SecretProviderOptions options) : base(options)
        {
            if (string.IsNullOrWhiteSpace(secretsDirectoryPath))
            {
                throw new ArgumentException("Requires a directory path inside the Docker container where the secrets are located", nameof(secretsDirectoryPath));
            }


            if (!Path.IsPathRooted(secretsDirectoryPath))
            {
                throw new ArgumentException("Requires an absolute directory path inside the Docker container to located the secrets", nameof(secretsDirectoryPath));
            }

            if (!Directory.Exists(secretsDirectoryPath))
            {
                throw new DirectoryNotFoundException($"The directory {secretsDirectoryPath} which is configured as secretsDirectoryPath does not exist.");
            }

            var configuration = new KeyPerFileConfigurationSource
            {
                FileProvider = new PhysicalFileProvider(secretsDirectoryPath),
                Optional = false
            };

            var provider = new KeyPerFileConfigurationProvider(configuration);
            provider.Load();

            _secretsDirectoryPath = secretsDirectoryPath;
            _provider = provider;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            return _provider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.Failure($"No '{secretName}' secret found in Docker secrets at '{_secretsDirectoryPath}'");
        }
    }
}
