using System;
using System.Threading.Tasks;
using Xunit;

namespace Arcus.Security.Tests.Core.Assertion
{
    public static class AssertProvider
    {
        public static async Task ContainsSecretAsync(ISecretProvider provider, string secretName, string secretValue, string secretVersion)
        {
#pragma warning disable S6966 // We should also test the synchronous version of the method.
            // ReSharper disable once MethodHasAsyncOverload
            Secret syncSecret = AssertResult.Success(provider.GetSecret(secretName));
            Assert.Equal(secretValue, syncSecret.Value);
            Assert.True(secretVersion is null || secretVersion == syncSecret.Version, $"expected '{secretName}' to have version '{secretVersion}', but got '{syncSecret.Version}'");

#pragma warning restore S6966

            Secret asyncSecret = AssertResult.Success(await provider.GetSecretAsync(secretName));
            Assert.Equal(secretValue, asyncSecret.Value);
            Assert.True(secretVersion is null || secretVersion == asyncSecret.Version, $"expected '{secretName}' to have version '{secretVersion}', but got '{asyncSecret.Version}'");
        }

        public static async Task ContainsSecretAsync(ISecretStore store, string secretName, string secretValue, string secretVersion, Action<SecretOptions> configureOptions = null)
        {
#pragma warning disable S6966 // We should also test the synchronous version of the method.
            // ReSharper disable once MethodHasAsyncOverload
            Secret syncSecret = AssertResult.Success(store.GetSecret(secretName, configureOptions));
            Assert.Equal(secretValue, syncSecret.Value);
            Assert.True(secretVersion is null || secretVersion == syncSecret.Version, $"expected '{secretName}' to have version '{secretVersion}', but got '{syncSecret.Version}'");

#pragma warning restore S6966

            Secret asyncSecret = AssertResult.Success(await store.GetSecretAsync(secretName, configureOptions));
            Assert.Equal(secretValue, asyncSecret.Value);
            Assert.True(secretVersion is null || secretVersion == asyncSecret.Version, $"expected '{secretName}' to have version '{secretVersion}', but got '{asyncSecret.Version}'");
        }

        public static async Task DoesNotContainSecretAsync(ISecretProvider provider, string secretName, params string[] errorParts)
        {
#pragma warning disable S6966 // We should also test the synchronous version of the method.
            // ReSharper disable once MethodHasAsyncOverload
            AssertResult.Failure(provider.GetSecret(secretName), errorParts);
#pragma warning restore S6966
            AssertResult.Failure(await provider.GetSecretAsync(secretName), errorParts);
        }

        public static Task ShouldContainSecretAsync(this ISecretProvider provider, Secret secret)
        {
            return ContainsSecretAsync(provider, secret.Name, secret.Value, secretVersion: null);
        }
    }
}
