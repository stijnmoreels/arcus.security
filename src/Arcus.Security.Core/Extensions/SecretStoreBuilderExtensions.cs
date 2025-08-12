using System;
using Arcus.Security;
using Arcus.Security.Core.Providers;
using Microsoft.Extensions.Configuration;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extends the <see cref="SecretStoreBuilder"/> to provide additional secret sources.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        public static SecretStoreBuilder AddEnvironmentVariables(this SecretStoreBuilder builder)
        {
            return AddEnvironmentVariables(builder, configureOptions: null);
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configureOptions">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddEnvironmentVariables(this SecretStoreBuilder builder, Action<EnvironmentVariableSecretProviderOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider((_, options) => new EnvironmentVariableSecretProvider(options), configureOptions);
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        public static SecretStoreBuilder AddConfiguration(this SecretStoreBuilder builder, IConfiguration configuration)
        {
            return AddConfiguration(builder, configuration, configureOptions: null);
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="configureOptions">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddConfiguration(this SecretStoreBuilder builder, IConfiguration configuration, Action<SecretProviderOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configuration);

            return builder.AddProvider((_, options) => new ConfigurationSecretProvider(configuration, options), configureOptions);
        }
    }
}
