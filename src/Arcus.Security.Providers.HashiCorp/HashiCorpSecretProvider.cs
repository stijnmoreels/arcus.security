using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace Arcus.Security.Providers.HashiCorp
{
    /// <summary>
    /// <para>
    ///     Represents an <see cref="ISecretProvider"/> that interacts with a HashiCorp Vault KeyVault engine to retrieve secrets.
    /// </para>
    /// <para>
    ///     See more information on HashiCorp Vault: <a href="https://www.vaultproject.io/docs" />.
    /// </para>
    /// </summary>
    public class HashiCorpSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HashiCorpSecretProvider"/> class.
        /// </summary>
        /// <param name="settings">The configuration and authentication settings to successfully connect to the HashiCorp Vault instance.</param>
        /// <param name="secretPath">The HashiCorp secret path available in the KeyValue engine where this secret provider should look for secrets.</param>
        /// <param name="options">The additional options to configure the HashiCorp Vault KeyValue.</param>
        /// <param name="logger">The logger instance to write diagnostic messages and track HashiCorp Vault dependencies.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="settings"/>,
        ///     or <paramref name="secretPath"/> is blank,
        ///     or <paramref name="options"/> is <c>null</c>
        ///     or the <paramref name="settings"/> doesn't contain a authentication method.</exception>
        /// <exception cref="ArgumentException">Thrown the <paramref name="settings"/> doesn't contain a valid Vault URI.</exception>
        public HashiCorpSecretProvider(
            VaultClientSettings settings,
            string secretPath,
            HashiCorpVaultOptions options,
            ILogger<HashiCorpSecretProvider> logger)
        {
            ArgumentNullException.ThrowIfNull(settings);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretPath);
            ArgumentNullException.ThrowIfNull(options);

            Options = options;
            SecretPath = secretPath;
            VaultClient = new VaultClient(settings);
            Logger = logger ?? NullLogger<HashiCorpSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the user-configurable options to configure and change the behavior of the HashiCorp KeyValue Vault.
        /// </summary>
        protected HashiCorpVaultOptions Options { get; }

        /// <summary>
        /// Gets the HashiCorp secret path available in the KeyValue engine where this secret provider should look for secrets.
        /// </summary>
        protected string SecretPath { get; }

        /// <summary>
        /// Gets the client to interact with the HashiCorp KeyValue Vault, based on the user-provided <see cref="VaultClientSettings"/>.
        /// </summary>
        protected IVaultClient VaultClient { get; }

        /// <summary>
        /// Gets the logger instance to write diagnostic messages and track HashiCorp Vault dependencies.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        public SecretResult GetSecret(string secretName)
        {
            throw new NotSupportedException(
                "HashiCorp secrets cannot be read synchronously, only asynchronous 'GetSecretAsync(...)' operations are supported");
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        public async Task<SecretResult> GetSecretAsync(string secretName)
        {
            SecretData result = await ReadSecretDataAsync();

            if (result.Data.TryGetValue(secretName, out object value) && value != null)
            {
                var version = result.Metadata?.Version.ToString();
                return SecretResult.Success(value.ToString(), version);
            }

            return SecretResult.Failure($"No secret found in HashiCorp secrets {Options.KeyValueVersion} {Options.KeyValueMountPoint} for '{secretName}'");
        }

        /// <summary>
        /// Read the secret data value in the HashiCorp KeyValue Vault, located at the provided <see cref="SecretPath"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown when the <see cref="Options"/>'s <see cref="HashiCorpVaultOptions.KeyValueVersion"/> represents an unknown secret engine version.
        /// </exception>
        protected async Task<SecretData> ReadSecretDataAsync()
        {
            switch (Options.KeyValueVersion)
            {
                case VaultKeyValueSecretEngineVersion.V1:
                    Secret<Dictionary<string, object>> secretV1 =
                        await VaultClient.V1.Secrets.KeyValue.V1.ReadSecretAsync(SecretPath, mountPoint: Options.KeyValueMountPoint);
                    return new SecretData { Data = secretV1.Data };

                case VaultKeyValueSecretEngineVersion.V2:
                    Secret<SecretData> secretV2 =
                        await VaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(SecretPath, mountPoint: Options.KeyValueMountPoint);
                    return secretV2.Data;

                default:
                    throw new ArgumentOutOfRangeException(nameof(Options), Options.KeyValueVersion, "Unknown HashiCorp Vault KeyValue secret engine version");
            }
        }
    }
}
