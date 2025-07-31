using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Bogus;
using Xunit;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Unit.Core
{
    public class DefaultSecretProviderTests
    {
        private static readonly Faker Bogus = new();

        private Dictionary<string, string> Secrets { get; } = GenerateSecrets();

        [Fact]
        public void GetSecret_WithoutCachingConfigured_GetsFreshSecret()
        {
            // Act
            var provider = InMemorySecretProvider.Create(Secrets);

            // Assert
            Secret secret = provider.GetAnySecret();
            provider.VerifyContainsSecret(secret, opt => opt.UseCache = Bogus.Random.Bool());

            Secret freshSecret = provider.RegenerateSecret(secret);
            provider.VerifyContainsSecret(freshSecret, opt => opt.UseCache = Bogus.Random.Bool());
        }

        [Fact]
        public void GetSecret_WithCachingConfigured_GetsCachedSecret()
        {
            // Act
            var provider = InMemorySecretProvider.Create(Secrets, options =>
            {
                options.UseCaching(Bogus.Date.Timespan());
            });

            // Assert
            Secret oldSecret = provider.GetAnySecret();
            provider.VerifyContainsSecret(oldSecret);

            provider.RegenerateSecret(oldSecret);
            provider.VerifyContainsSecret(oldSecret);
        }

        [Fact]
        public void GetSecretWithIgnoreCache_WithCachingConfigured_GetsFreshSecret()
        {
            // Act
            var provider = InMemorySecretProvider.Create(Secrets, options =>
            {
                options.UseCaching(Bogus.Date.Timespan());
            });

            // Assert
            Secret oldSecret = provider.GetAnySecret();
            provider.VerifyContainsSecret(oldSecret, opt => opt.UseCache = true);

            Secret freshSecret = provider.RegenerateSecret(oldSecret);
            provider.VerifyContainsSecret(freshSecret, opt => opt.UseCache = false);
        }

        [Fact]
        public async Task GetSecret_WithMappedSecretName_GetsSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var mapper = WhenSecretNameMapped();

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddInMemory(Secrets, options =>
                {
                    options.MapSecretName(mapper);
                });
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();
            Secret anySecret = provider.GetAnySecret();

            await secretStore.ShouldContainSecretAsync(mapper(anySecret.Name), anySecret.Value);
        }

        [Fact]
        public void GetProvider_WithName_Succeeds()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = Bogus.Lorem.Sentence();

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddInMemory(Secrets, options =>
                {
                    options.Name = providerName;
                });
            });

            // Assert
            secretStore.ShouldContainProvider<InMemorySecretProvider>(providerName);
        }

        private static Dictionary<string, string> GenerateSecrets()
        {
            return Bogus.Make(Bogus.Random.Int(1, 5), () => new KeyValuePair<string, string>(Bogus.Random.Guid().ToString(), Bogus.Lorem.Word()))
                        .ToDictionary();
        }

        private static SecretStoreTestContext GivenSecretStore()
        {
            return Given();
        }
    }
}
