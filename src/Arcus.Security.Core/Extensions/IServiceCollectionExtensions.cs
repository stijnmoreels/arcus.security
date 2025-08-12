using System;
using Arcus.Security;
using Microsoft.Extensions.Hosting;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions on the <see cref="IServiceCollection"/> related to the secret store.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IServiceCollectionExtensions
    {
        /// <summary>
        /// Configures a secret store in the application with a given set of <see cref="ISecretProvider"/>s.
        /// </summary>
        /// <remarks>
        ///     Multiple calls will aggregate the registered <see cref="ISecretProvider"/> into a single secret store.
        /// </remarks>
        /// <param name="services">The services to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IServiceCollection AddSecretStore(this IServiceCollection services, Action<SecretStoreBuilder> configureSecretStores)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(configureSecretStores);

            var builder = new SecretStoreBuilder(services);
            configureSecretStores(builder);
            builder.RegisterSecretStore();

            return services;
        }
    }
}
