using System;
using Arcus.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="IHostBuilder"/> to configure the <see cref="ISecretProvider"/> as in a more consumer-friendly manner.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IHostBuilderExtensions
    {
        /// <summary>
        /// Configures a secret store in the application with a given set of <see cref="ISecretProvider"/>s.
        /// </summary>
        /// <remarks>
        ///     Multiple calls will aggregate the registered <see cref="ISecretProvider"/> into a single secret store.
        /// </remarks>
        /// <param name="hostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="hostBuilder"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            return ConfigureSecretStore(hostBuilder, (_, config, secretStores) => configureSecretStores(config, secretStores));
        }

        /// <summary>
        /// Configures a secret store in the application with a given set of <see cref="ISecretProvider"/>s.
        /// </summary>
        /// <remarks>
        ///     Multiple calls will aggregate the registered <see cref="ISecretProvider"/> into a single secret store.
        /// </remarks>
        /// <param name="hostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="hostBuilder"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<HostBuilderContext, IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            ArgumentNullException.ThrowIfNull(hostBuilder);
            ArgumentNullException.ThrowIfNull(configureSecretStores);

            return hostBuilder.ConfigureServices((context, services) =>
            {
                services.AddSecretStore(stores => configureSecretStores(context, context.Configuration, stores));
            });
        }
    }
}
