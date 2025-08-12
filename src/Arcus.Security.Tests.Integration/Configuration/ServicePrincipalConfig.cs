using System;
using Arcus.Testing;
using Azure.Core;
using Azure.Identity;

namespace Arcus.Security.Tests.Integration.Configuration
{
    internal class ServicePrincipalConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ServicePrincipalConfig"/> class.
        /// </summary>
        public ServicePrincipalConfig(string tenantId, string clientId, string clientSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
            ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);

            TenantId = tenantId;
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        public string ClientId { get; }
        public string ClientSecret { get; }
        public string TenantId { get; }

        public TokenCredential GetCredential()
        {
            return new ClientSecretCredential(TenantId, ClientId, ClientSecret);
        }
    }

    internal static class ServicePrincipalConfigExtensions
    {
        public static ServicePrincipalConfig GetServicePrincipal(this TestConfig config)
        {
            string tenantId = config["Arcus:Tenant"];
            string clientId = config["Arcus:ServicePrincipal:ApplicationId"];
            string clientSecret = config["Arcus:ServicePrincipal:AccessKey"];

            return new ServicePrincipalConfig(tenantId, clientId, clientSecret);
        }
    }
}
