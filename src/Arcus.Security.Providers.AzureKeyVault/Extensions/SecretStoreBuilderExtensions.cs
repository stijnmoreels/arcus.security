using System;
using Arcus.Security.Providers.AzureKeyVault;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to provide easy addition the Azure Key Vault secrets in the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="vaultUri">The absolute URI to the Azure Key vault (usually something like: 'https://&lt;your-vault-name&gt;.vault.azure.net/').</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="vaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(this SecretStoreBuilder builder,
            string vaultUri,
            TokenCredential tokenCredential)
        {
            return AddAzureKeyVault(builder, vaultUri, tokenCredential, configureProviderOptions: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="vaultUri">The absolute URI to the Azure Key vault (usually something like: 'https://&lt;your-vault-name&gt;.vault.azure.net/').</param>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance.</param>
        /// <param name="configureProviderOptions">The optional additional options to configure the secret provider registration in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="tokenCredential"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="vaultUri"/> is blank.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            string vaultUri,
            TokenCredential tokenCredential,
            Action<KeyVaultSecretProviderOptions> configureProviderOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentException.ThrowIfNullOrWhiteSpace(vaultUri);
            ArgumentNullException.ThrowIfNull(tokenCredential);

            return AddAzureKeyVault(builder, _ => new SecretClient(new Uri(vaultUri), tokenCredential), configureProviderOptions);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="implementationFactory">The function to create the client to interact with the Azure Key Vault.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            Func<IServiceProvider, SecretClient> implementationFactory)
        {
            return AddAzureKeyVault(builder, implementationFactory, configureProviderOptions: null);
        }

        /// <summary>
        /// Adds Azure Key Vault as a secret source.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="implementationFactory">The function to create the client to interact with the Azure Key Vault.</param>
        /// <param name="configureProviderOptions">The optional additional options to configure the secret provider registration in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/>, <paramref name="implementationFactory"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddAzureKeyVault(
            this SecretStoreBuilder builder,
            Func<IServiceProvider, SecretClient> implementationFactory,
            Action<KeyVaultSecretProviderOptions> configureProviderOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(implementationFactory);

            return builder.AddProvider((serviceProvider, context, options) =>
            {
                return new KeyVaultSecretProvider(implementationFactory(serviceProvider), context, options);

            }, configureProviderOptions);
        }
    }
}
