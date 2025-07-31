using System;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class EnvironmentVariableSecretProviderTests
    {
        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariables_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var secretStore = SecretStoreTestContext.Given();

            using var variable = TemporaryEnvironmentVariable.Create(secretKey, expected);

            // Act
            secretStore.WhenSecretProvider(store => store.AddEnvironmentVariables());

            // Assert
            await secretStore.ShouldContainSecretAsync(secretKey, expected);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithOptions_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string secretKey = "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var secretStore = SecretStoreTestContext.Given();
            using var variable = TemporaryEnvironmentVariable.Create(secretKey, expected);

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddEnvironmentVariables(options =>
                {
                    options.Target = EnvironmentVariableTarget.Process;
                });
            });

            // Assert
            await secretStore.ShouldContainSecretAsync(secretKey, expected);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithPrefix_UsesEnvironmentVariableSecrets()
        {
            // Arrange
            string prefix = "ARCUS_";
            string secretKey = prefix + "MySecret";
            string expected = $"secret-{Guid.NewGuid()}";

            var secretStore = SecretStoreTestContext.Given();
            using var variable = TemporaryEnvironmentVariable.Create(secretKey, expected);

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddEnvironmentVariables(options => options.Prefix = prefix);
            });

            // Assert
            string nonPrefixedSecret = secretKey[prefix.Length..];
            await secretStore.ShouldContainSecretAsync(nonPrefixedSecret, expected);
        }

        [Fact]
        public async Task ConfigureSecretStore_AddEnvironmentVariablesWithPrefix_CantFindEnvironmentVariableWithPrefix()
        {
            // Arrange
            string unknownPrefix = "UNKNOWN_";
            string secretKey = "MySecret";

            var secretStore = SecretStoreTestContext.Given();
            using var variable = TemporaryEnvironmentVariable.Create(secretKey, value: $"secret-{Guid.NewGuid()}");

            // Act
            secretStore.WhenSecretProvider(store =>
            {
                store.AddEnvironmentVariables(options => options.Prefix = unknownPrefix);
            });

            // Assert
            await secretStore.ShouldNotContainSecretAsync(secretKey);
        }
    }
}
