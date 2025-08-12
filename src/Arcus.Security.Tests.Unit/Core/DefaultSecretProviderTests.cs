using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Unit.Core
{
    public class DefaultSecretProviderTests
    {
        private readonly ILogger _logger;
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultSecretProviderTests"/> class.
        /// </summary>
        public DefaultSecretProviderTests(ITestOutputHelper outputWriter)
        {
            _logger = new XunitTestLogger(outputWriter);
        }

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
        public async Task GetSecret_WithCachingConfigured_GetsCachedSecretViaProvider()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory(Secrets);
                store.UseCaching(Bogus.Date.Timespan());
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            Secret oldSecret = provider.GetAnySecret();
            await secretStore.ShouldContainSecretAsync(oldSecret);

            provider.RegenerateSecret(oldSecret);
            await secretStore.ShouldContainSecretAsync(oldSecret);
        }

        [Fact]
        public async Task GetSecretWithIgnoreCache_WithCachingConfigured_GetsFreshSecretViaProvider()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.UseCaching(Bogus.Date.Timespan());
                store.AddInMemory(Secrets);
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            Secret oldSecret = provider.GetAnySecret();
            await secretStore.ShouldContainSecretAsync(oldSecret, opt => opt.UseCache = false);

            Secret freshSecret = provider.RegenerateSecret(oldSecret);
            await secretStore.ShouldContainSecretAsync(freshSecret, opt => opt.UseCache = false);
        }

        [Fact]
        public async Task GetSecret_WithMappedSecretName_GetsSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var mapper = WhenSecretNameMapped();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory(Secrets, options =>
                {
                    options.MapSecretName(mapper);
                });
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            var secret = Secret.Generate();
            provider.Secrets[mapper(secret.Name)] = secret.Value;

            await secretStore.ShouldContainSecretAsync(secret.Name, secret.Value);
        }

        [Fact]
        public void GetProvider_WithName_Succeeds()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = Bogus.Lorem.Sentence();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory(Secrets, options =>
                {
                    options.ProviderName = providerName;
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

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(_logger);
        }
    }
}
