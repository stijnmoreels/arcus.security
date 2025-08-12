using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core.Providers;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Unit.Core
{
    public class ConfigurationSecretProviderTests
    {
        private readonly ILogger _logger;
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationSecretProviderTests"/> class.
        /// </summary>
        public ConfigurationSecretProviderTests(ITestOutputHelper outputWriter)
        {
            _logger = new XunitTestLogger(outputWriter);
        }

        [Fact]
        public async Task AddConfiguration_WithDefault_UsesIConfiguration()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = Secret.Generate();
            secretStore.WhenAppConfiguration(config =>
            {
                config.AddInMemoryCollection([secret]);
            });

            // Act
            secretStore.WhenSecretStore((config, store) =>
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
            using var secretStore = GivenSecretStore();

            string name = $"config-{Bogus.Random.Guid()}";
            Func<string, string> mapSecretName = WhenSecretNameMapped();
            var secret = Secret.Generate();

            secretStore.WhenAppConfiguration(config =>
            {
                config.AddInMemoryCollection(
                [
                    new KeyValuePair<string, string>(mapSecretName(secret.Name), secret.Value)
                ]);
            });

            // Act
            secretStore.WhenSecretStore((config, store) =>
            {
                store.UseCaching(Bogus.Date.Timespan());
                store.AddConfiguration(config, opt =>
                {
                    opt.ProviderName = name;
                    opt.MapSecretName(mapSecretName);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<ConfigurationSecretProvider>(name);
            await secretStore.ShouldContainSecretAsync(secret);
            await secretStore.ShouldNotContainSecretAsync($"unknown-secret-{Bogus.Random.Guid()}");
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEmptyConfiguration_CantFindConfigKey()
        {
            // Arrange
            var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore((config, store) => store.AddConfiguration(config));

            // Assert
            secretStore.ShouldContainProvider<ConfigurationSecretProvider>();
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

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(_logger);
        }
    }
}
