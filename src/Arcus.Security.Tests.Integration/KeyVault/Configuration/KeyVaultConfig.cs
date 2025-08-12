using System;
using Arcus.Security.Tests.Core.Assertion;
using Arcus.Security.Tests.Integration.Configuration;
using Arcus.Testing;
using Azure.Security.KeyVault.Secrets;

namespace Arcus.Security.Tests.Integration.KeyVault.Configuration
{
    internal class KeyVaultConfig
    {
        public KeyVaultConfig(string vaultUri, Secret secret, ServicePrincipalConfig servicePrincipal)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(vaultUri);
            ArgumentNullException.ThrowIfNull(secret);
            ArgumentNullException.ThrowIfNull(servicePrincipal);

            ServicePrincipal = servicePrincipal;
            VaultUri = vaultUri;
            AvailableSecret = secret;
        }


        public string VaultUri { get; }
        public Secret AvailableSecret { get; }
        public ServicePrincipalConfig ServicePrincipal { get; }

        public SecretClient GetClient()
        {
            return new SecretClient(new Uri(VaultUri), ServicePrincipal.GetCredential());
        }
    }

    internal static class KeyVaultConfigExtensions
    {
        public static KeyVaultConfig GetKeyVault(this TestConfig config)
        {
            string vaultUri =
                $"https://{config.GetRequiredValue("Arcus:KeyVault:Name")}.vault.azure.net/";

            var secret = new Secret(
                config["Arcus:KeyVault:TestSecretName"],
                config["Arcus:KeyVault:TestSecretValue"],
                config["Arcus:KeyVault:TestSecretVersion"]);

            ServicePrincipalConfig servicePrincipalConfig = config.GetServicePrincipal();
            return new KeyVaultConfig(vaultUri, secret, servicePrincipalConfig);
        }
    }
}
