using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Xunit;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CompositeSecretProviderTests : UnitTest
    {
        public CompositeSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task GetProvider_WithMultipleWithSameName_CreatesSubGroup()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = $"{Bogus.Lorem.Word()} secrets";
            var secret1 = Secret.Generate();
            var secret2 = Secret.Generate();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory(new Dictionary<string, string> { [secret1.Name] = secret1.Value }, options => options.ProviderName = providerName);
                store.AddInMemory(new Dictionary<string, string> { [secret2.Name] = secret2.Value }, options => options.ProviderName = providerName);
            });

            // Assert
            var provider = secretStore.ShouldContainProvider(providerName);
            await provider.ShouldContainSecretAsync(secret1);
            await provider.ShouldContainSecretAsync(secret1);
        }

        [Fact]
        public void GetProvider_WithoutProviderName_UsesTypeName()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddProvider(new DummySecretProvider());
            });

            // Assert
            secretStore.ShouldContainProvider(nameof(DummySecretProvider));
        }

        private sealed class DummySecretProvider : ISecretProvider
        {
            public SecretResult GetSecret(string secretName, SecretOptions options)
            {
                throw new System.NotImplementedException();
            }
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return SecretStoreTestContext.Given(Logger);
        }
    }
}
