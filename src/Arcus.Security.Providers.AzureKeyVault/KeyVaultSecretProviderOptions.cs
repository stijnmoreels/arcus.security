using System.Collections.Generic;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    /// Represents the available options to be configured on the <see cref="KeyVaultSecretProvider"/>.
    /// </summary>
    public class KeyVaultSecretProviderOptions : SecretProviderOptions
    {
        private readonly Dictionary<string, int> _allowedSecretVersions = new();

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProviderOptions"/> class.
        /// </summary>
        public KeyVaultSecretProviderOptions() : base(typeof(KeyVaultSecretProvider))
        {
        }

        /// <summary>
        /// Configures the Azure Key Vault <paramref name="secretName"/> to have a certain amount of <paramref name="allowedVersions"/>
        /// when calling the <see cref="KeyVaultSecretProvider.GetSecretsAsync"/>.
        /// </summary>
        /// <param name="secretName">The name of the Azure Key Vault secret that can have multiple versions.</param>
        /// <param name="allowedVersions">The maximum allowed versions the secret can have upon retrieving the secret.</param>
        public void AddVersionedSecret(string secretName, int allowedVersions)
        {
            _allowedSecretVersions[secretName] = allowedVersions;
        }

        internal bool IsAllowedToRetrieveAnother(string secretName, int currentVersions)
        {
            return !_allowedSecretVersions.TryGetValue(secretName, out int allowedVersions)
                   || currentVersions < allowedVersions;
        }
    }
}
