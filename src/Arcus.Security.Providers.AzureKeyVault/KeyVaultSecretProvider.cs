using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Polly;
using Polly.Retry;
using RetryPolicy = Polly.Retry.RetryPolicy;
using SecretProperties = Azure.Security.KeyVault.Secrets.SecretProperties;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    ///     Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider : DefaultSecretProvider
    {
        private readonly SecretClient _secretClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        internal KeyVaultSecretProvider(
            SecretClient client,
            SecretProviderOptions options)
            : base(options)
        {
            _secretClient = client;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            return ThrottleTooManyRequests(secretName, () => _secretClient.GetSecret(secretName));
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override Task<SecretResult> GetSecretAsync(string secretName)
        {
            return ThrottleTooManyRequestsAsync(secretName, async () => await _secretClient.GetSecretAsync(secretName));
        }

        /// <summary>
        /// Stores a secret value with a given secret name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="secretValue">The value of the secret</param>
        /// <returns>Returns a <see cref="SecretResult"/> that contains the latest information for the given secret</returns>
        public async Task<SecretResult> StoreSecretAsync(string secretName, string secretValue)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

            SecretResult result =
                await ThrottleTooManyRequestsAsync(secretName,
                    () => _secretClient.SetSecretAsync(secretName, secretValue));

            UpdateSecretInCache(secretName, result);
            return result;
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        public virtual async Task<SecretsResult> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentOutOfRangeException.ThrowIfLessThan(amountOfVersions, 1);

            (bool isFound, string[] versions) = await DetermineVersionsAsync(secretName);
            if (!isFound)
            {
                return SecretsResult.Create([SecretResult.Failure($"No '{secretName}' secret found in Azure Key Vault secrets")]);
            }

            var results = new Collection<SecretResult>();
            foreach (string version in versions)
            {
                if (results.Count == amountOfVersions)
                {
                    break;
                }

                SecretResult result = await ThrottleTooManyRequestsAsync(secretName, () => _secretClient.GetSecretAsync(secretName, version));
                results.Add(result);
            }

            return SecretsResult.Create(results);
        }

        private async Task<(bool isFound, string[] versions)> DetermineVersionsAsync(string secretName)
        {
            return await ThrottleTooManyRequestsAsync(async () =>
            {
                AsyncPageable<SecretProperties> properties = _secretClient.GetPropertiesOfSecretVersionsAsync(secretName);

                var versions = new Collection<SecretProperties>();
                await foreach (SecretProperties property in properties)
                {
                    if (property.Enabled is true)
                    {
                        versions.Add(property);
                    }
                }

                var versionNumbers =
                    versions.OrderByDescending(version => version.CreatedOn)
                            .Select(version => version.Version)
                            .ToArray();

                return (isFound: true, versionNumbers);

            }, notFoundValue: (isFound: false, []));
        }

        private static async Task<SecretResult> ThrottleTooManyRequestsAsync(
            string secretName,
            Func<Task<Response<KeyVaultSecret>>> secretOperation)
        {
            return await ThrottleTooManyRequestsAsync(async () =>
            {
                KeyVaultSecret response = await secretOperation();

                return SecretResult.Success(secretName,
                    response.Value,
                    response.Properties.Version,
                    response.Properties.ExpiresOn ?? default);

            }, notFoundValue: SecretResult.Failure($"No '{secretName}' secret found in Azure Key Vault secrets"));
        }

        private static async Task<TResult> ThrottleTooManyRequestsAsync<TResult>(
            Func<Task<TResult>> secretOperation,
            TResult notFoundValue)
        {
            try
            {
                AsyncRetryPolicy policy =
                    GetExponentialBackOffRetryAsyncPolicy<Exception>(
                        exception => exception is RequestFailedException { Status: 429 });

                var response = await policy.ExecuteAsync(secretOperation);
                return response;
            }
            catch (RequestFailedException requestFailedException)
            {
                if (requestFailedException.Status == 404)
                {
                    return notFoundValue;
                }

                throw;
            }
        }

        private static AsyncRetryPolicy GetExponentialBackOffRetryAsyncPolicy<TException>(Func<TException, bool> exceptionPredicate)
            where TException : Exception
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle(exceptionPredicate)
                         .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)));
        }

        private static SecretResult ThrottleTooManyRequests(string secretName, Func<KeyVaultSecret> secretOperation)
        {
            try
            {
                RetryPolicy retryPolicy = GetExponentialBackOffRetrySyncPolicy<Exception>(
                    ex => ex is RequestFailedException { Status: 429 });

                var response = retryPolicy.Execute(secretOperation);

                return SecretResult.Success(secretName,
                    response.Value,
                    response.Properties.Version,
                    response.Properties.ExpiresOn ?? default);
            }
            catch (RequestFailedException requestFailedException)
            {
                if (requestFailedException.Status == 404)
                {
                    return SecretResult.Failure($"No '{secretName}' secret found in Azure Key Vault secrets", requestFailedException);
                }

                throw;
            }
        }

        private static RetryPolicy GetExponentialBackOffRetrySyncPolicy<TException>(Func<TException, bool> exceptionPredicate)
            where TException : Exception
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle(exceptionPredicate)
                         .WaitAndRetry(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)));
        }
    }
}
