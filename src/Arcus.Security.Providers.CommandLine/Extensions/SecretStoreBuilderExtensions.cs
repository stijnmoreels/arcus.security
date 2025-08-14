using System;
using Arcus.Security;
using Arcus.Security.Providers.CommandLine;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Provides a series of extensions to add the command line types to the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments)
        {
            return AddCommandLine(builder, arguments, configureOptions: null);
        }

        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="configureOptions">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, Action<SecretProviderOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(arguments);

            return builder.AddProvider(CommandLineSecretProvider.Create(arguments), configureOptions);
        }
    }
}
