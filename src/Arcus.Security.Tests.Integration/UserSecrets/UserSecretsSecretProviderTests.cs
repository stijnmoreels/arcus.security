using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Providers.UserSecrets;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Core.Fixture;
using Arcus.Security.Tests.Integration.UserSecrets.Fixture;
using Microsoft.Extensions.Hosting;
using Xunit;
using Xunit.Abstractions;
using static Arcus.Security.Tests.Core.Fixture.SecretStoreTestContext;

namespace Arcus.Security.Tests.Integration.UserSecrets
{
    public class UserSecretsSecretProviderTests : IntegrationTest, IDisposable
    {
        private readonly TemporaryUserSecretsStorage _userSecrets;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProviderTests"/> class.
        /// </summary>
        public UserSecretsSecretProviderTests(ITestOutputHelper outputWriter) : base(outputWriter)
        {
            _userSecrets = TemporaryUserSecretsStorage.CreateIfNotExists(Logger);
        }

        public static IEnumerable<object[]> AddUserSecretsVariations =>
        [
            [(SecretStoreBuilder store) => { store.AddUserSecrets<TemporaryUserSecretsStorage>(); }],
            [(SecretStoreBuilder store) => { store.AddUserSecrets(typeof(TemporaryUserSecretsStorage).Assembly); }],
            [(SecretStoreBuilder store) => { store.AddUserSecrets(TemporaryUserSecretsStorage.TestSecretsId); }]
        ];

        [Theory]
        [MemberData(nameof(AddUserSecretsVariations))]
        public async Task AddUserSecrets_WithDefault_UserSecretsAsSecrets(Action<SecretStoreBuilder> addUserSecrets)
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            var secret = Secret.Generate();
            WhenUserSecret(secret);

            // Act
            secretStore.WhenSecretStore(addUserSecrets);

            // Assert
            secretStore.ShouldContainProvider<UserSecretsSecretProvider>();
            await secretStore.ShouldContainSecretAsync(secret);
        }

        public static IEnumerable<object[]> AddUserSecretsOptionsVariations =>
        [
            [(Action<SecretProviderOptions> configureOptions) => (SecretStoreBuilder store) => { store.AddUserSecrets<TemporaryUserSecretsStorage>(configureOptions); }],
            [(Action<SecretProviderOptions> configureOptions) => (SecretStoreBuilder store) => { store.AddUserSecrets(typeof(TemporaryUserSecretsStorage).Assembly, configureOptions); }],
            [(Action<SecretProviderOptions> configureOptions) => (SecretStoreBuilder store) => { store.AddUserSecrets(TemporaryUserSecretsStorage.TestSecretsId, configureOptions); }]
        ];

        [Theory]
        [MemberData(nameof(AddUserSecretsOptionsVariations))]
        public async Task AddUserSecrets_WithOptions_UserSecretsAsSecrets(Func<Action<SecretProviderOptions>, Action<SecretStoreBuilder>> addUserSecrets)
        {
            // Arrange
            using var secretStore = GivenSecretStore();

            string providerName = Bogus.Lorem.Word();
            Func<string, string> mapSecretName = WhenSecretNameMapped();
            var secret = Secret.Generate();

            WhenUserSecret(mapSecretName(secret.Name), secret.Value);

            // Act
            secretStore.WhenSecretStore(addUserSecrets(options =>
            {
                options.ProviderName = providerName;
                options.MapSecretName(mapSecretName);
            }));

            // Assert
            secretStore.ShouldContainProvider<UserSecretsSecretProvider>(providerName);
            await secretStore.ShouldContainSecretAsync(secret);
        }

        private void WhenUserSecret(Secret secret)
        {
            WhenUserSecret(secret.Name, secret.Value);
        }

        private void WhenUserSecret(string secretName, string secretValue)
        {
            _userSecrets.AddUserSecret(secretName, secretValue);
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
            _userSecrets.Dispose();
        }
    }
}