using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Arcus.Security.Tests.Core.Fixture
{
    public sealed class SecretStoreTestContext : IDisposable
    {
        private bool _alreadyBuild;
        private IHost _host;
        private readonly HostBuilder _builder = new();
        private readonly ILogger _logger;

        private static readonly Faker Bogus = new();

        private SecretStoreTestContext(ILogger logger)
        {
            _logger = logger ?? NullLogger.Instance;
            _builder.ConfigureLogging(logging =>
            {
                logging.SetMinimumLevel(LogLevel.Trace)
                       .AddProvider(new DelegateLoggerProvider(logger));
            });
        }

        private sealed class DelegateLoggerProvider(ILogger logger) : ILoggerProvider
        {
            public ILogger CreateLogger(string categoryName) => logger;
            public void Dispose() { }
        }

        public static SecretStoreTestContext Given(ILogger logger)
        {
            return new SecretStoreTestContext(logger);
        }

        public static Func<string, string> WhenSecretNameMapped()
        {
            return Bogus.Random.Int(1, 4) switch
            {
                1 => secretName => "Prefix:" + secretName.ToUpperInvariant(),
                2 => secretName => secretName.ToLowerInvariant() + "-suffix",
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

        public void WhenSecretStore(Action<SecretStoreBuilder> configureSecretStore)
        {
            WhenSecretStore((_, stores) => configureSecretStore(stores));
        }

        public void WhenSecretStore(Action<IConfiguration, SecretStoreBuilder> configureSecretStore)
        {
            _builder.ConfigureSecretStore((config, stores) =>
            {
                if (Bogus.Random.Bool())
                {
                    stores.AddProvider(new NeverFoundSecretProvider(), configureOptions: null);
                }

                if (Bogus.Random.Bool())
                {
                    stores.AddProvider(new AlwaysFailsSecretProvider(), configureOptions: null);
                }

                configureSecretStore(config, stores);
            });
        }

        private sealed class NeverFoundSecretProvider : ISecretProvider
        {
            public SecretResult GetSecret(string secretName)
            {
                return SecretResult.Failure($"No secret found for '{secretName}'");
            }
        }

        private sealed class AlwaysFailsSecretProvider : ISecretProvider
        {
            public SecretResult GetSecret(string secretName)
            {
                throw new KeyNotFoundException("Sabotage, always fails secret retrieval");
            }
        }

        public TProvider ShouldContainProvider<TProvider>(string name = null) where TProvider : ISecretProvider
        {
            name ??= typeof(TProvider).Name;

            var store = GetHost().Services.GetRequiredService<ISecretStore>();

            Assert.NotNull(store.GetProvider(name));
            var provider = store.GetProvider<TProvider>(name);
            Assert.NotNull(provider);

            return provider;
        }

        public ISecretProvider ShouldContainProvider(string name)
        {
            var store = GetHost().Services.GetRequiredService<ISecretStore>();

            ISecretProvider provider = store.GetProvider(name);
            Assert.NotNull(provider);

            return provider;
        }

        public Task ShouldContainSecretAsync(Secret secret, Action<SecretOptions> configureOptions = null)
        {
            return ShouldContainSecretAsync(secret.Name, secret.Value, secret.Version, configureOptions);
        }

        public Task ShouldContainSecretAsync(SecretResult secret, Action<SecretOptions> configureOptions = null)
        {
            return ShouldContainSecretAsync(secret.Name, secret.Value, secret.Version, configureOptions);
        }

        public async Task ShouldContainSecretAsync(string secretName, string secretValue, string secretVersion = null, Action<SecretOptions> configureOptions = null)
        {
            var store = GetHost().Services.GetRequiredService<ISecretStore>();
            await AssertProvider.ContainsSecretAsync(store, secretName, secretValue, secretVersion, configureOptions);
            await AssertProvider.DoesNotContainSecretAsync(store, $"unknown-secret-{Guid.NewGuid()}");
        }

        public async Task ShouldNotContainSecretAsync(Secret secret, params string[] errorParts)
        {
            await ShouldNotContainSecretAsync(secret.Name, errorParts);
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
