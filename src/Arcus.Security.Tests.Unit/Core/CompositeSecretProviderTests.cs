using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Bogus;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Unit.Core
{
    public class CompositeSecretProviderTests : UnitTest
    {
        public CompositeSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        private Dictionary<string, string> Secrets { get; } = GenerateSecrets();

        [Fact]
        public void GetProvider_WithName_Succeeds()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = Bogus.Lorem.Sentence();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory(options =>
                {
                    options.ProviderName = providerName;
                });
            });

            // Assert
            secretStore.ShouldContainProvider<InMemorySecretProvider>(providerName);
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
        public async Task GetSecret_WithoutCachingConfigured_GetsFreshSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory();
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();
            Secret secret = provider.GetAnySecret();

            await secretStore.ShouldContainSecretAsync(secret, opt => opt.UseCache = Bogus.Random.Bool());

            Secret freshSecret = provider.RegenerateSecret(secret);
            await secretStore.ShouldContainSecretAsync(freshSecret, opt => opt.UseCache = Bogus.Random.Bool());
        }

        [Fact]
        public async Task GetSecret_WithCachingConfigured_GetsCachedSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddInMemory();
                store.UseCaching();
            });

            // Assert
            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            Secret oldSecret = provider.GetAnySecret();
            await secretStore.ShouldContainSecretAsync(oldSecret);

            provider.RegenerateSecret(oldSecret);
            await secretStore.ShouldContainSecretAsync(oldSecret);
        }

        [Fact]
        public async Task GetSecretWithIgnoreCache_WithCachingConfigured_GetsFreshSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();
            secretStore.WhenSecretStore(store =>
            {
                store.UseCaching();
                store.AddInMemory();
            });

            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            Secret oldSecret = provider.GetAnySecret();
            await secretStore.ShouldContainSecretAsync(oldSecret, opt => opt.UseCache = false);

            // Act
            Secret freshSecret = provider.RegenerateSecret(oldSecret);

            // Assert
            await secretStore.ShouldContainSecretAsync(freshSecret, opt => opt.UseCache = false);
        }

        [Fact]
        public async Task GetCachedSecret_AfterInvalidateSecret_GetsFreshSecret()
        {
            // Arrange
            using var secretStore = GivenSecretStore();
            secretStore.WhenSecretStore(store =>
            {
                store.UseCaching();
                store.AddInMemory();
            });

            var provider = secretStore.ShouldContainProvider<InMemorySecretProvider>();

            Secret oldSecret = provider.GetAnySecret();
            await secretStore.ShouldContainSecretAsync(oldSecret);

            Secret freshSecret = provider.RegenerateSecret(oldSecret);

            // Act
            await secretStore.WhenSecretStoreAsync(store => store.Cache.InvalidateSecretAsync(oldSecret));

            // Assert
            await secretStore.ShouldContainSecretAsync(freshSecret);
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
            public SecretResult GetSecret(string secretName)
            {
                throw new System.NotImplementedException();
            }
        }

        private static Dictionary<string, string> GenerateSecrets()
        {
            return Bogus.Make(Bogus.Random.Int(1, 5), () => new KeyValuePair<string, string>(Bogus.Random.Guid().ToString(), Bogus.Lorem.Word()))
                        .ToDictionary();
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(Logger);
        }
    }

    internal static class ISecretStoreExtensions
    {
        private static readonly Faker Bogus = new();

        internal static void UseCaching(this SecretStoreBuilder builder)
        {
            builder.UseCaching(Bogus.Date.Timespan());
        }

        internal static Task InvalidateSecretAsync(this SecretStoreCaching caching, Secret secret)
        {
            return caching.InvalidateSecretAsync(secret.Name);
        }
    }
}
