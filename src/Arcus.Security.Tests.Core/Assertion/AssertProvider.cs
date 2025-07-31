using System;
using System.Threading.Tasks;
using Xunit;

namespace Arcus.Security.Tests.Core.Assertion
{
    public static class AssertProvider
    {
        public static async Task ContainsSecretAsync(ISecretProvider provider, string secretName, string secretValue, Action<SecretOptions> configureOptions = null)
        {
#pragma warning disable S6966 // We should also test the synchronous version of the method.
            // ReSharper disable once MethodHasAsyncOverload
            Secret syncSecret = AssertResult.Success(provider.GetSecret(secretName, configureOptions));
            Assert.Equal(secretValue, syncSecret.Value);

#pragma warning restore S6966

            Secret asyncSecret = AssertResult.Success(await provider.GetSecretAsync(secretName, configureOptions));
            Assert.Equal(secretValue, asyncSecret.Value);
        }

        public static async Task DoesNotContainSecretAsync(ISecretProvider provider, string secretName, params string[] errorParts)
        {
#pragma warning disable S6966 // We should also test the synchronous version of the method.
            // ReSharper disable once MethodHasAsyncOverload
            AssertResult.Failure(provider.GetSecret(secretName), errorParts);
#pragma warning restore S6966
            AssertResult.Failure(await provider.GetSecretAsync(secretName), errorParts);
        }
    }
}
