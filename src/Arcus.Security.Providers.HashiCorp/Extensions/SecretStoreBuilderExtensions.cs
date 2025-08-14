using System;
using Arcus.Security;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VaultSharp;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to add the HashiCorp Vault as <see cref="ISecretProvider"/>.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> doesn't have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(this SecretStoreBuilder builder, VaultClientSettings settings, string secretPath)
        {
            return AddHashiCorpVault(builder, settings, secretPath, configureOptions: null);
        }

        /// <summary>
        /// <para>
        ///     Adds the secrets of a HashiCorp Vault KeyValue engine to the secret store.
        /// </para>
        /// <para>
        ///     See more information on HashiCorp: <a href="https://www.vaultproject.io/docs" />.
        /// </para>
        /// </summary>
        /// <param name="builder">The builder to add the HashiCorp secrets from the KeyValue Vault to.</param>
        /// <param name="settings"></param>
        /// <param name="secretPath">The secret path where the secret provider should look for secrets.</param>
        /// <param name="configureOptions">The function to set the additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="builder"/>, <paramref name="settings"/> or <paramref name="secretPath"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="settings"/> does not have a valid Vault server URI or a missing authentication method,
        ///     or the <paramref name="secretPath"/> is blank.
        /// </exception>
        public static SecretStoreBuilder AddHashiCorpVault(
            this SecretStoreBuilder builder,
            VaultClientSettings settings,
            string secretPath,
            Action<HashiCorpVaultOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(settings);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretPath);

            return builder.AddProvider((serviceProvider, _, options) =>
            {
                var logger = serviceProvider.GetService<ILogger<HashiCorpSecretProvider>>();
                return new HashiCorpSecretProvider(settings, secretPath, options, logger);

            }, configureOptions);
        }
    }
}
