using System;
using System.Linq;
using Arcus.Security;
using Arcus.Security.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the entry point for extending the available secret store in the application.
    /// </summary>
    public class SecretStoreBuilder
    {
        private readonly DefaultSecretStoreContext _context = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilder"/> class.
        /// </summary>
        /// <param name="services">The available registered services in the application.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> is <c>null</c>.</exception>
        public SecretStoreBuilder(IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);
            Services = services;
        }

        /// <summary>
        /// Gets the available registered services in the application.
        /// </summary>
        public IServiceCollection Services { get; }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider>(TProvider secretProvider)
            where TProvider : ISecretProvider
        {
            return AddProvider(secretProvider, configureOptions: null);
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider>(TProvider secretProvider, Action<SecretProviderOptions> configureOptions)
            where TProvider : ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(secretProvider);
            Services.AddSingleton(_ =>
            {
                var options = new SecretProviderOptions(typeof(TProvider));
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(secretProvider, options);
            });

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider>(
            Func<IServiceProvider, ISecretStoreContext, TProvider> implementationFactory,
            Action<SecretProviderOptions> configureOptions)
            where TProvider : ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new SecretProviderOptions(typeof(TProvider));
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, _context), options);
            });

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <typeparam name="TProvider">The custom user-implemented <see cref="ISecretProvider"/> type to register in the secret store.</typeparam>
        /// <typeparam name="TOptions">The custom user-implemented <see cref="SecretProviderOptions"/> to configure the <typeparamref name="TProvider"/>.</typeparam>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider, TOptions>(
            Func<IServiceProvider, ISecretStoreContext, TOptions, TProvider> implementationFactory,
            Action<TOptions> configureOptions)
            where TProvider : ISecretProvider
            where TOptions : SecretProviderOptions, new()
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new TOptions();
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, _context, options), options);
            });

            return this;
        }

        /// <summary>
        /// Configures the secret provider to use caching with a sliding expiration <paramref name="duration"/>.
        /// </summary>
        /// <param name="duration">The expiration time when the secret should be invalidated in the cache.</param>
        public void UseCaching(TimeSpan duration)
        {
            _context.Cache.SetDuration(duration);
        }

        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when one or more <see cref="ISecretProvider"/> was registered with the same name.</exception>
        internal void RegisterSecretStore()
        {
            Services.TryAddSingleton<ISecretStore>(serviceProvider =>
            {
                var registrations = serviceProvider.GetServices<SecretProviderRegistration>().ToArray();
                var logger = serviceProvider.GetService<ILoggerFactory>().CreateLogger("secret store");

                return new CompositeSecretProvider(registrations, _context.Cache, logger);
            });
        }

        internal sealed class DefaultSecretStoreContext : ISecretStoreContext
        {
            public SecretStoreCaching Cache { get; set; } = new();
        }
    }
}