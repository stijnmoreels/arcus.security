using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.KeyVault.Configuration;
using Arcus.Security.Tests.Integration.KeyVault.Fixture;
using Bogus;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    public class KeyVaultSecretProviderTests : IntegrationTest, IAsyncLifetime
    {
        public KeyVaultSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
        }

        private TemporaryKeyVaultState KeyVault { get; set; }
        private Secret AvailableSecret => KeyVault.Config.AvailableSecret;

        [Fact]
        public async Task AddKeyVault_WithDefault_UsesKeyVaultSecretsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddAzureKeyVault(KeyVault);
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<KeyVaultSecretProvider>();
            await secretStore.ShouldContainSecretAsync(AvailableSecret);

            SecretResult addedSecret = await provider.StoreSecretAsync(Secret.Generate());
            await secretStore.ShouldContainSecretAsync(addedSecret);
            await KeyVault.ShouldContainSecretAsync(addedSecret);
        }

        [Fact]
        public async Task AddKeyVault_WithOptions_UsesKeyVaultSecretsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var providerName = $"{Bogus.Lorem.Word()} secrets";
            string prefix = Bogus.Lorem.Word();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddAzureKeyVault(KeyVault, options =>
                {
                    options.ProviderName = providerName;
                });
                store.AddAzureKeyVault(KeyVault, options =>
                {
                    options.MapSecretName(name => name[prefix.Length..]);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<KeyVaultSecretProvider>();
            secretStore.ShouldContainProvider<KeyVaultSecretProvider>(providerName);
            await secretStore.ShouldContainSecretAsync(AvailableSecret);
            await secretStore.ShouldContainSecretAsync(prefix + AvailableSecret.Name, AvailableSecret.Value);
        }

        [Fact]
        public async Task AddKeyVault_WithMultipleVersions_UsesKeyVaultVersionedSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string secretName = $"{Bogus.Lorem.Word()}secret";
            Secret[] storedVersions = await KeyVault.WhenSecretVersionsAvailableAsync(secretName);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddAzureKeyVault(KeyVault);
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<KeyVaultSecretProvider>();
            await provider.ShouldContainSecretVersionsAsync(secretName, storedVersions);
        }

        [Fact]
        public async Task AddKeyVaultWithVersionedSecret_WithMultipleVersions_UsesKeyVaultVersionedSecretsWithinBounds()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string secretName = $"{Bogus.Lorem.Word()}secret";
            Secret[] storedVersions = await KeyVault.WhenSecretVersionsAvailableAsync(secretName);
            int allowedVersions = Bogus.Random.Int(1, storedVersions.Length);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddAzureKeyVault(KeyVault, options =>
                {
                    options.AddVersionedSecret(secretName, allowedVersions);
                });
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<KeyVaultSecretProvider>();
            Secret[] actualVersions = await provider.ShouldContainSecretVersionsAsync(secretName, storedVersions);
            Assert.True(actualVersions.Length <= allowedVersions, "secret versions should always be within the bounds of the configured allowed versions");
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return SecretStoreTestContext.Given(Logger);
        }

        public Task InitializeAsync()
        {
            KeyVault = TemporaryKeyVaultState.Create(Configuration.GetKeyVault(), Logger);
            return Task.CompletedTask;
        }

        public async Task DisposeAsync()
        {
            await KeyVault.DisposeAsync();
        }
    }

    internal static class KeyVaultSecretProviderExtensions
    {
        private static readonly Faker Bogus = new();

        internal static SecretStoreBuilder AddAzureKeyVault(this SecretStoreBuilder store, TemporaryKeyVaultState keyVaultState, Action<KeyVaultSecretProviderOptions> configureOptions = null)
        {
            var keyVault = keyVaultState.Config;
            return configureOptions is null
                ? store.AddAzureKeyVault(keyVault.VaultUri, keyVault.ServicePrincipal.GetCredential())
                : store.AddAzureKeyVault(keyVault.VaultUri, keyVault.ServicePrincipal.GetCredential(), configureOptions);
        }

        internal static Task<SecretResult> StoreSecretAsync(this KeyVaultSecretProvider provider, Secret secret)
        {
            return provider.StoreSecretAsync(secret.Name, secret.Value);
        }

        internal static async Task<Secret[]> ShouldContainSecretVersionsAsync(this KeyVaultSecretProvider provider, string secretName, Secret[] storedVersions)
        {
            int amountOfVersions = Bogus.Random.Int(1, storedVersions.Length);
            Secret[] result = AssertResult.Success(await provider.GetSecretsAsync(secretName, amountOfVersions));

            Assert.NotEmpty(result);
            Assert.All(result, actual => Assert.Contains(actual, storedVersions));

            return result;
        }
    }
}
