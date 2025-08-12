using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Providers.DockerSecrets;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.DockerSecrets.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Integration.DockerSecrets
{
    public class DockerSecretsSecretProviderTests : IntegrationTest, IDisposable
    {
        private readonly TemporaryDockerSecretsStorage _dockerSecrets;

        public DockerSecretsSecretProviderTests(ITestOutputHelper testOutput) : base(testOutput)
        {
            _dockerSecrets = TemporaryDockerSecretsStorage.CreateIfNotExists(Logger);
        }

        public static IEnumerable<object[]> DockerSecretsVariations =>
        [
           [() => Secret.Generate(), (SecretStoreTestContext store, Secret secret) => store.ShouldContainSecretAsync(secret)],
           [() => new Secret(Bogus.Lorem.Word() + "__" + Bogus.Lorem.Word(), Bogus.Random.Guid().ToString()), (SecretStoreTestContext store, Secret secret) => store.ShouldContainSecretAsync(secret.Name.Replace("__", ":"), secret.Value)]
        ];

        [Theory]
        [MemberData(nameof(DockerSecretsVariations))]
        public async Task AddDockerSecrets_WithDefault_UsesDockerSecretsAsSecrets(Func<Secret> createSecret, Func<SecretStoreTestContext, Secret, Task> assertContainsSecretAsync)
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = createSecret();
            _dockerSecrets.AddDockerSecret(secret);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddDockerSecrets(_dockerSecrets.Directory);
            });

            // Assert
            secretStore.ShouldContainProvider<DockerSecretsSecretProvider>();
            await assertContainsSecretAsync(secretStore, secret);
        }

        [Fact]
        public async Task AddDockerSecrets_WithOptions_UsesDockerSecretsAsSecrets()
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var providerName = $"{Bogus.Lorem.Word()} secrets";
            var secret = Secret.Generate();
            Func<string, string> mapSecretName = WhenSecretNameMapped();

            _dockerSecrets.AddDockerSecret(mapSecretName(secret.Name), secret.Value);

            // Act
            secretStore.WhenSecretStore(store =>
            {
                store.AddDockerSecrets(_dockerSecrets.Directory, options =>
                {
                    options.ProviderName = providerName;
                    options.MapSecretName(mapSecretName);
                });
            });

            // Assert
            secretStore.ShouldContainProvider<DockerSecretsSecretProvider>(providerName);
            await secretStore.ShouldContainSecretAsync(secret.Name, secret.Value);
        }

        [Theory]
        [InlineData("/foo/bar", typeof(DirectoryNotFoundException))]
        [InlineData("./foo", typeof(ArgumentException))]
        public async Task DockerSecrets_WithNonExistingAbsolutePath_Fails(string secretsPath, Type exceptionType)
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            // Act
            secretStore.WhenSecretStore(store => store.AddDockerSecrets(secretsPath));

            // Assert
            await Assert.ThrowsAsync(exceptionType, () => secretStore.ShouldContainSecretAsync(Secret.Generate()));
        }

        private SecretStoreTestContext GivenSecretStore()
        {
            return Given(Logger);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _dockerSecrets.Dispose();
        }
    }

    internal static class DockerSecretsExtensions
    {
        public static void AddDockerSecret(this TemporaryDockerSecretsStorage storage, Secret secret)
        {
            storage.AddDockerSecret(secret.Name, secret.Value);
        }

        public static SecretStoreBuilder AddDockerSecrets(this SecretStoreBuilder builder, DirectoryInfo directory, Action<SecretProviderOptions> configureOptions = null)
        {
            return builder.AddDockerSecrets(directory.FullName, configureOptions);
        }
    }
}
