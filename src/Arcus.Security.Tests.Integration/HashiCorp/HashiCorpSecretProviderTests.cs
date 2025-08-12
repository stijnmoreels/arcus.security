using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.HashiCorp.Hosting;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Integration.HashiCorp
{
    public class HashiCorpSecretProviderTests : IntegrationTest, IAsyncLifetime
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProviderTests"/> class.
        /// </summary>
        public HashiCorpSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        private HashiCorpVaultTestServer HashiCorpVault { get; set; }

        [Fact]
        public async Task AddHashiCorp_WithDefault_UsesHashiCorpSecretsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = Secret.Generate();
            string secretPath = await HashiCorpVault.StoreSecretAsync(secret);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddHashiCorpVault(HashiCorpVault, secretPath);
            });

            // Assert
            secretStore.ShouldContainProvider<HashiCorpSecretProvider>();
            await secretStore.ShouldContainSecretAsync(secret);
        }

        [Fact]
        public async Task AddHashiCorp_WithOptions_UsesHashiCorpSecretsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = $"{Bogus.Lorem.Word()} secrets";
            var secret = Secret.Generate();
            Func<string, string> mapSecretName = WhenSecretNameMapped();

            string secretPath = await HashiCorpVault.StoreSecretAsync(mapSecretName(secret.Name), secret.Value);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddHashiCorpVault(HashiCorpVault, secretPath, options =>
                {
                    options.ProviderName = providerName;
                    options.MapSecretName(mapSecretName);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<HashiCorpSecretProvider>(providerName);
            await secretStore.ShouldContainSecretAsync(secret.Name, secret.Value);
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(Logger);
        }

        public async Task InitializeAsync()
        {
            HashiCorpVault = await HashiCorpVaultTestServer.StartServerAsync(Configuration, Logger);
        }

        public async Task DisposeAsync()
        {
            await HashiCorpVault.DisposeAsync();
        }
    }

    internal static class HashiCorpSecretProviderExtensions
    {
        internal static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder store,
            HashiCorpVaultTestServer server,
            string secretPath,
            Action<HashiCorpVaultOptions> configureOptions = null)
        {
            return store.AddHashiCorpVault(server.Settings, secretPath, options =>
            {
                options.KeyValueVersion = server.EngineVersion;
                if (server.CustomMountPoint != null)
                {
                    options.KeyValueMountPoint = server.CustomMountPoint;
                }

                configureOptions?.Invoke(options);
            });
        }

        internal static Task<string> StoreSecretAsync(this HashiCorpVaultTestServer server, Secret secret)
        {
            return server.StoreSecretAsync(secret.Name, secret.Value);
        }
    }
}
