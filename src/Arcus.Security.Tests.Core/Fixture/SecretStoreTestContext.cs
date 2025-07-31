using System;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Arcus.Security.Tests.Core.Fixture
{
    public sealed class SecretStoreTestContext : IDisposable
    {
        private bool _alreadyBuild;
        private IHost _host;
        private readonly HostBuilder _builder = new();

        private static readonly Faker Bogus = new();

        public static SecretStoreTestContext Given()
        {
            return new SecretStoreTestContext();
        }

        public static Func<string, string> WhenSecretNameMapped()
        {
            return Bogus.Random.Int(1, 4) switch
            {
                1 => secretName => "Prefix added by mutation:" + secretName.ToUpperInvariant(),
                2 => secretName => secretName.ToLowerInvariant() + "-suffix-added-by-mutation",
                3 => secretName => secretName.Replace("-", "_"),
                4 => secretName => new string(secretName.Reverse().ToArray()),
            };
        }

        public void WhenServices(Action<IServiceCollection> configureServices)
        {
            _builder.ConfigureServices(configureServices);
        }

        public void WhenAppConfiguration(Action<IConfigurationBuilder> configureAppConfig)
        {
            _builder.ConfigureAppConfiguration(configureAppConfig);
        }

        public void WhenSecretProvider(Action<SecretStoreBuilder> configureSecretStore)
        {
            WhenSecretProvider((_, stores) => configureSecretStore(stores));
        }

        public void WhenSecretProvider(Action<IConfiguration, SecretStoreBuilder> configureSecretStore)
        {
            _builder.ConfigureSecretStore((config, stores) =>
            {
                if (Bogus.Random.Bool())
                {
                    stores.AddProvider(new NeverFoundSecretProvider());
                }

                configureSecretStore(config, stores);
            });
        }

        private sealed class NeverFoundSecretProvider : DefaultSecretProvider
        {
            protected override SecretResult GetSecret(string secretName)
            {
                return SecretResult.Failure($"No secret found for '{secretName}'");
            }
        }

        public TProvider ShouldContainProvider<TProvider>(string name = null) where TProvider : ISecretProvider
        {
            return GetHost().Services
                .GetRequiredService<ISecretStore>()
                .GetProvider<TProvider>(name ?? typeof(TProvider).Name);
        }

        public Task ShouldContainSecretAsync(Secret secret)
        {
            return ShouldContainSecretAsync(secret.Name, secret.Value);
        }

        public async Task ShouldContainSecretAsync(string secretName, string secretValue)
        {
            var store = GetHost().Services.GetRequiredService<ISecretStore>();
            await AssertProvider.ContainsSecretAsync(store, secretName, secretValue);
        }

        public async Task ShouldNotContainSecretAsync(string secretName, params string[] errorParts)
        {
            var store = GetHost().Services.GetRequiredService<ISecretStore>();
            await AssertProvider.DoesNotContainSecretAsync(store, secretName, errorParts);
        }

        private IHost GetHost()
        {
            if (!_alreadyBuild)
            {
                _host = _builder.Build();
                _alreadyBuild = true;
            }

            return _host;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _host?.Dispose();
        }
    }
}
