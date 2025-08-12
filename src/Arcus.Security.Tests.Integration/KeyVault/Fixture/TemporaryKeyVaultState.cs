using System;
using System.Threading.Tasks;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Arcus.Testing;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault.Fixture
{
    internal class TemporaryKeyVaultState : IAsyncDisposable
    {
        private readonly SecretClient _client;
        private readonly DisposableCollection _disposables;
        private readonly ILogger _logger;

        private TemporaryKeyVaultState(KeyVaultConfig config, SecretClient client, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(config);
            ArgumentNullException.ThrowIfNull(client);

            _client = client;
            _logger = logger ?? NullLogger.Instance;
            _disposables = new DisposableCollection(_logger);

            Config = config;
        }

        public KeyVaultConfig Config { get; }

        public static TemporaryKeyVaultState Create(KeyVaultConfig keyVault, ILogger logger)
        {
            var client = keyVault.GetClient();
            return new TemporaryKeyVaultState(keyVault, client, logger);
        }

        public async Task ShouldContainSecretAsync(SecretResult secret)
        {
            ArgumentNullException.ThrowIfNull(secret);

            KeyVaultSecret found = await _client.GetSecretAsync(secret.Name);
            Assert.Equal(secret.Value, found.Value);

            _disposables.Add(AsyncDisposable.Create(async () =>
            {
                _logger.LogTrace("[Test:Teardown] Delete Azure Key Vault secret '{SecretName}' from vault '{VaultUri}'", secret.Name, Config.VaultUri);
                await _client.StartDeleteSecretAsync(secret.Name);
            }));
        }

        public async ValueTask DisposeAsync()
        {
            await using var _ = _disposables.ConfigureAwait(false);
        }
    }
}
