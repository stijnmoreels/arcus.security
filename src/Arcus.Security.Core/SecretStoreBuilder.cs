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
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider>(TProvider secretProvider)
            where TProvider : ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(secretProvider);
            Services.AddSingleton(_ =>
            {
                var options = new SecretProviderOptions(typeof(TProvider));
                return new SecretProviderRegistration(secretProvider, options);
            });

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider>(
            Func<IServiceProvider, SecretProviderOptions, TProvider> implementationFactory,
            Action<SecretProviderOptions> configureOptions)
            where TProvider : ISecretProvider
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new SecretProviderOptions(typeof(TProvider));
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, options), options);
            });

            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="implementationFactory">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="implementationFactory"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider<TProvider, TOptions>(
            Func<IServiceProvider, TOptions, TProvider> implementationFactory,
            Action<TOptions> configureOptions)
            where TProvider : ISecretProvider
            where TOptions : SecretProviderOptions, new()
        {
            ArgumentNullException.ThrowIfNull(implementationFactory);

            Services.AddSingleton(serviceProvider =>
            {
                var options = new TOptions();
                configureOptions?.Invoke(options);

                return new SecretProviderRegistration(implementationFactory(serviceProvider, options), options);
            });

            return this;
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
                var logger = serviceProvider.GetService<ILogger<ISecretStore>>();

                return new CompositeSecretProvider(registrations, logger);
            });

            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ISecretStore>());
        }
    }
}