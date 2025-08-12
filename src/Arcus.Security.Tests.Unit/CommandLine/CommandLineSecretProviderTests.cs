using System;
using System.Threading.Tasks;
using Arcus.Security.Providers.CommandLine;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Unit.CommandLine
{
    public class CommandLineSecretProviderTests
    {
        private readonly ILogger _logger;
        private static readonly Faker Bogus = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandLineSecretProviderTests"/> class.
        /// </summary>
        public CommandLineSecretProviderTests(ITestOutputHelper outputWriter)
        {
            _logger = new XunitTestLogger(outputWriter);
        }

        [Fact]
        public async Task AddCommandLine_WithDefault_UsesCommandLineArgumentsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = Secret.Generate();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddCommandLine([$"--{secret.Name}={secret.Value}"]);
            });

            // Assert
            secretStore.ShouldContainProvider<CommandLineSecretProvider>();
            await secretStore.ShouldContainSecretAsync(secret);
        }

        [Fact]
        public async Task AddCommandLine_WithOptions_UsesCommandLineArgumentsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var providerName = $"{Bogus.Lorem.Word()} secrets";
            var secret = Secret.Generate();
            Func<string, string> mapSecretName = WhenSecretNameMapped();

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddCommandLine([$"--{mapSecretName(secret.Name)}={secret.Value}"], options =>
                {
                    options.ProviderName = providerName;
                    options.MapSecretName(mapSecretName);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<CommandLineSecretProvider>(providerName);
            await secretStore.ShouldContainSecretAsync(secret);
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(_logger);
        }
    }
}