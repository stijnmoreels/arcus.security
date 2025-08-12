using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Providers;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Testing;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Integration.Core
{
    public class EnvironmentVariableSecretProviderTests : IntegrationTest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProviderTests"/> class.
        /// </summary>
        public EnvironmentVariableSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
        }

        [Fact]
        public async Task AddEnvironmentVariables_WithDefault_UsesEnvironmentVariablesAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = Secret.Generate();
            using var variable = WhenEnvironmentVariable(secret);

            // Act
            secretStore.WhenSecretStore(store => store.AddEnvironmentVariables());

            // Assert
            secretStore.ShouldContainProvider<EnvironmentVariableSecretProvider>();
            await secretStore.ShouldContainSecretAsync(secret);
        }

        [Fact]
        public async Task AddEnvironmentVariables_WithPrefix_UsesOnlySelectEnvironmentVariablesAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var prefix = Bogus.Lorem.Word().ToUpperInvariant() + "_";
            var secret1 = Secret.Generate(name => prefix + name);
            var secret2 = Secret.Generate();

            using var variable1 = WhenEnvironmentVariable(secret1);
            using var variable2 = WhenEnvironmentVariable(secret2);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddEnvironmentVariables(options => options.Prefix = prefix);
                store.AddEnvironmentVariables(options => options.Prefix = "ignored_prefix");
            });

            // Assert
            await secretStore.ShouldContainSecretAsync(secret1.Name[prefix.Length..], secret1.Value);
            await secretStore.ShouldNotContainSecretAsync(secret2.Name);
        }

        [Fact]
        public async Task AddEnvironmentVariables_WithOptions_UsesEnvironmentVariablesAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var providerName = Bogus.Lorem.Word() + " secrets";
            var prefix = Bogus.Lorem.Word().ToUpperInvariant() + "_";
            var secret1 = Secret.Generate(name => prefix + name);
            var secret2 = Secret.Generate();
            Func<string, string> mapSecretName = WhenSecretNameMapped();

            using var variable1 = WhenEnvironmentVariable(secret1);
            using var variable2 = WhenEnvironmentVariable(secret2, mapSecretName);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddEnvironmentVariables(options =>
                {
                    options.ProviderName = providerName;
                    options.Prefix = prefix;
                });
                store.AddEnvironmentVariables(options =>
                {
                    options.MapSecretName(mapSecretName);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<EnvironmentVariableSecretProvider>();
            secretStore.ShouldContainProvider<EnvironmentVariableSecretProvider>(providerName);

            await secretStore.ShouldContainSecretAsync(secret1.Name[prefix.Length..], secret1.Value);
            await secretStore.ShouldNotContainSecretAsync(secret1);
            await secretStore.ShouldContainSecretAsync(secret2);
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(Logger);
        }

        private TemporaryEnvironmentVariable WhenEnvironmentVariable(Secret secret, Func<string, string> mapSecretName = null)
        {
            return WhenEnvironmentVariable(mapSecretName is null ? secret.Name : mapSecretName(secret.Name), secret.Value);
        }

        private TemporaryEnvironmentVariable WhenEnvironmentVariable(string secretName, string secretValue)
        {
            return TemporaryEnvironmentVariable.SetIfNotExists(secretName, secretValue, Logger);
        }
    }
}
