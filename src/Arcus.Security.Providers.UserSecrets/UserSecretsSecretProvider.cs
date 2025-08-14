using System;
using System.IO;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.FileProviders;

namespace Arcus.Security.Providers.UserSecrets
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides user secrets.
    /// </summary>
    public sealed class UserSecretsSecretProvider : ISecretProvider, IDisposable
    {
        private const string SecretsFileName = "secrets.json";

        private readonly JsonConfigurationProvider _jsonProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProvider"/> class.
        /// </summary>
        internal UserSecretsSecretProvider(JsonConfigurationProvider jsonProvider)
        {
            ArgumentNullException.ThrowIfNull(jsonProvider);
            _jsonProvider = jsonProvider;
        }

        internal static UserSecretsSecretProvider Create(string userSecretsId)
        {
            string directoryPath = GetUserSecretsDirectoryPath(userSecretsId);
            JsonConfigurationSource source = CreateJsonFileSource(directoryPath);

            var provider = new JsonConfigurationProvider(source);
            provider.Load();

            return new UserSecretsSecretProvider(provider);
        }

        private static string GetUserSecretsDirectoryPath(string usersSecretsId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(usersSecretsId);

            string secretPath = PathHelper.GetSecretsPathFromSecretsId(usersSecretsId);
            string directoryPath = Path.GetDirectoryName(secretPath);

            return directoryPath;
        }

        private static JsonConfigurationSource CreateJsonFileSource(string directoryPath)
        {
            IFileProvider fileProvider = null;
            if (Directory.Exists(directoryPath))
            {
                fileProvider = new PhysicalFileProvider(directoryPath);
            }

            var source = new JsonConfigurationSource
            {
                FileProvider = fileProvider,
                Path = SecretsFileName,
                Optional = false
            };

            source.ResolveFileProvider();
            source.FileProvider ??= new PhysicalFileProvider(AppContext.BaseDirectory);

            return source;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        public SecretResult GetSecret(string secretName)
        {
            return _jsonProvider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.Failure($"No secret found '{secretName}' in user secrets at '{_jsonProvider.Source.Path}'");
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _jsonProvider?.Dispose();
        }
    }
}
