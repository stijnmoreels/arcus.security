using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace Arcus.Security.Tests.Integration.DockerSecrets.Fixture
{
    internal sealed class TemporaryDockerSecretsStorage : IDisposable
    {
        private readonly ILogger _logger;

        private TemporaryDockerSecretsStorage(DirectoryInfo dockerSecretsDirectory, ILogger logger)
        {
            _logger = logger;
            Directory = dockerSecretsDirectory;
        }

        public DirectoryInfo Directory { get; }

        public static TemporaryDockerSecretsStorage CreateIfNotExists(ILogger logger)
        {
            var dockerSecretsDirectory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"DockerSecrets-{Guid.NewGuid()}"));

            logger.LogTrace("[Test:Setup] Create new DockerSecrets local directory at '{DirectoryPath}'", dockerSecretsDirectory.FullName);
            dockerSecretsDirectory.Create();

            return new TemporaryDockerSecretsStorage(dockerSecretsDirectory, logger);
        }

        public void AddDockerSecret(string secretName, string secretValue)
        {
            _logger.LogTrace("[Test] Add new DockerSecret '{Name}' to local storage at '{DirectoryPath}'", secretName, Directory.FullName);
            File.WriteAllTextAsync(Path.Combine(Directory.FullName, secretName), secretValue);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (Directory.Exists)
            {
                _logger.LogTrace("[Test:Teardown] Delete DockerSecrets local directory at '{DirectoryPath}'", Directory.FullName);
                Directory.Delete(recursive: true);
            }
            else
            {
                _logger.LogTrace("[Test:Teardown] DockerSecrets local directory already deleted at '{DirectoryPath}'", Directory.FullName);
            }
        }
    }
}
