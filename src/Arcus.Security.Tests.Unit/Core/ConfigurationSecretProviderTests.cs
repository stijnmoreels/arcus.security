using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Providers;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class ConfigurationSecretProviderTests
    {
        private static readonly Faker Bogus = new();

        [Fact]
        public async Task AddConfiguration_WithDefault_UsesIConfiguration()
        {
            // Arrange
            var secret = Secret.Generate();
            using var secretStore = GivenSecretStore();

            secretStore.WhenAppConfiguration(config =>
            {
                config.AddInMemoryCollection([secret]);
            });

            // Act
            secretStore.WhenSecretProvider((config, store) =>
            {
                store.AddConfiguration(config);
            });

            // Assert
            secretStore.ShouldContainProvider<ConfigurationSecretProvider>();
            await secretStore.ShouldContainSecretAsync(secret);
        }

        [Fact]
        public async Task AddConfiguration_WithOptions_UsesIConfigurationWithOptions()
        {
            // Arrange
            string name = $"config-{Bogus.Random.Guid()}";
            var secret = Secret.Generate();
            using var secretStore = GivenSecretStore();

            secretStore.WhenAppConfiguration(config =>
            {
                config.AddInMemoryCollection([secret]);
            });

            // Act
            secretStore.WhenSecretProvider((config, store) =>
            {
                store.AddConfiguration(config, opt =>
                {
                    opt.Name = name;
                });
            });

            // Assert
            secretStore.ShouldContainProvider<ConfigurationSecretProvider>(name);
            await secretStore.ShouldContainSecretAsync(secret);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEmptyConfiguration_CantFindConfigKey()
        {
            // Arrange
            var secretStore = SecretStoreTestContext.Given();

            // Act
            secretStore.WhenSecretProvider((config, store) => store.AddConfiguration(config));

            // Assert
            await secretStore.ShouldNotContainSecretAsync("MySecret");
        }

        [Fact]
        public void ConfigureSecretStore_WithoutConfiguration_Throws()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((_, stores) => stores.AddConfiguration(configuration: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }

        private static SecretStoreTestContext GivenSecretStore()
        {
            return SecretStoreTestContext.Given();
        }
    }
}
