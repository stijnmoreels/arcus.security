using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.AzureKeyVault;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.KeyVault.Fixture;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Integration.KeyVault
{
    [Trait(name: "Category", value: "Integration")]
    public partial class KeyVaultSecretProviderTests
    {
        [Fact]
        public async Task KeyVaultSecretProvider_WithUserAssignedManagedIdentity_GetSecret_Succeeds()
        {
            // Arrange
            using var _ = UseTemporaryManagedIdentityConnection();
            var secretStore = SecretStoreTestContext.Given();

            secretStore.WhenSecretProvider(store =>
            {
                store.AddAzureKeyVault(VaultUri, new DefaultAzureCredential());
            });

            // Act / Assert
            await secretStore.ShouldContainSecretAsync(TestSecretName, TestSecretValue);

            var notExistingSecretName = $"secret-{Guid.NewGuid():N}";
            await secretStore.ShouldNotContainSecretAsync(notExistingSecretName);
        }

        [Fact]
        public async Task KeyVaultSecretProvider_StoreSecret_Succeeds()
        {
            // Arrange
            var secretName = $"Test-Secret-{Guid.NewGuid()}";
            var secretValue = Guid.NewGuid().ToString();

            using TemporaryManagedIdentityConnection connection = UseTemporaryManagedIdentityConnection();
            var secretStore = SecretStoreTestContext.Given();

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddAzureKeyVault(VaultUri, new DefaultAzureCredential());
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<KeyVaultSecretProvider>();
            try
            {
                SecretResult storedSecret = await provider.StoreSecretAsync(secretName, secretValue);
                Assert.Equal(secretValue, storedSecret.Value);

                await secretStore.ShouldContainSecretAsync(secretName, secretValue);
            }
            finally
            {
                var client = new SecretClient(new Uri(VaultUri), new DefaultAzureCredential());
                await client.StartDeleteSecretAsync(secretName);
            }
        }
    }
}
