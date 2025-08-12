using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ISecretStore
    {
        private readonly SecretStoreOptions _options;
        private readonly IReadOnlyCollection<SecretProviderRegistration> _secretProviders;
        private readonly Dictionary<string, Lazy<ISecretProvider>> _secretProvidersByName;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderRegistrations">The sequence of all available registered secret provider registrations.</param>
        /// <param name="options"></param>
        /// <param name="logger">The logger instance to write diagnostic messages during the retrieval of secrets via the registered <paramref name="secretProviderRegistrations"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderRegistrations"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderRegistrations"/> contains any <c>null</c> values.</exception>
        internal CompositeSecretProvider(
            IReadOnlyCollection<SecretProviderRegistration> secretProviderRegistrations,
            SecretStoreOptions options,
            ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(secretProviderRegistrations);
            ArgumentNullException.ThrowIfNull(options);

            var registrations = secretProviderRegistrations.Where(r => r != null).ToArray();

            _secretProviders = registrations;
            _options = options;
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;

            _secretProvidersByName = CreateGroupedSecretProviders(registrations, logger);
        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <typeparam name="TProvider">The concrete type of the secret provider implementation.</typeparam>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the type name in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        public TProvider GetProvider<TProvider>(string providerName) where TProvider : ISecretProvider
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

            if (_secretProvidersByName.TryGetValue(providerName, out Lazy<ISecretProvider> subset))
            {
                if (subset.Value is TProvider concrete)
                {
                    return concrete;
                }

                throw new InvalidOperationException(
                    $"Cannot retrieve the named '{nameof(ISecretProvider)}' of type '{typeof(TProvider).Name}' because more than one provider was registered with the name '{providerName}':" +
                    $"{string.Concat(_secretProvidersByName.Keys.Select(key => $"{Environment.NewLine}- {key}"))}" +
                    $"{Environment.NewLine}→ Use the '{nameof(ISecretProvider)}' as generic type to retrieve a sub-group of providers with the same name");
            }

            throw new KeyNotFoundException(
                $"Cannot retrieve the named '{nameof(ISecretProvider)}' of type '{typeof(TProvider).Name}' because no secret provider was registered with the name '{providerName}' of that type:" +
                $"{(_secretProvidersByName.Count == 0
                    ? "No secret providers were registered in the secret store"
                    : string.Concat(_secretProvidersByName.Keys.Select(key => $"{Environment.NewLine}- {key}")))}" +
                $"{Environment.NewLine}→ Register the secret provider with a name using the overloads during registration (i.e. `stores.AddAzureKeyVault(..., options => options.Name = \"AdminSecrets\")`)");
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public SecretResult GetSecret(string secretName, SecretOptions options)
        {
            return GetSecretCoreAsync(secretName, (provider, name) =>
            {
                return Task.FromResult(provider.GetSecret(name, options));

            }, options).Result;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The </param>
        /// <param name="options"></param>
        public Task<SecretResult> GetSecretAsync(string secretName, SecretOptions options)
        {
            return GetSecretCoreAsync(secretName, (provider, name) => provider.GetSecretAsync(name, options), options);
        }

        private async Task<SecretResult> GetSecretCoreAsync(
            string secretName,
            Func<ISecretProvider, string, Task<SecretResult>> getSecretAsync,
            SecretOptions options)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            options ??= new SecretOptions();

            var failures = new Collection<(string providerName, SecretResult)>();
            foreach (SecretProviderRegistration source in _secretProviders)
            {
                string providerName = source.Options.ProviderName;
                try
                {
                    var mapped = source.Options.SecretNameMapper(secretName);
                    if (_options.TryGetCachedSecret(secretName, options, out SecretResult cached))
                    {
                        return cached;
                    }

                    SecretResult result = await getSecretAsync(source.SecretProvider, mapped);
                    if (result is null)
                    {
                        _logger.LogWarning("Secret store could not found secret '{SecretName}' in secret provider '{ProviderName}' as it returned 'null' upon querying provider", secretName, providerName);
                        continue;
                    }

                    if (result.IsSuccess)
                    {
                        _logger.LogDebug("Secret store found secret '{SecretName}' in secret provider '{ProviderName}'", secretName, providerName);
                        _options.UpdateSecretInCache(secretName, result, options);
                        return result;
                    }

                    _logger.LogDebug("Secret store could not found secret '{SecretName}' in secret provider '{ProviderName}'", secretName, providerName);
                    failures.Add((providerName, result));
                }
                catch (Exception exception)
                {
                    failures.Add((providerName, SecretResult.Failure($"Secret provider '{providerName}' failed to find secret '{secretName}' due to an unexpected failure", exception)));
                    _logger.LogWarning(exception, "Secret store could not found secret '{SecretName}' in secret provider '{ProviderName}' due to an exception while querying for the secret", secretName, providerName);
                }
            }

            SecretResult noneFoundFailure = CreateSecretResultNoneFoundFailure(secretName, failures);
            return noneFoundFailure;
        }

        private SecretResult CreateSecretResultNoneFoundFailure(string secretName, Collection<(string providerName, SecretResult result)> failures)
        {
            string messages = failures.Count == 0
                ? "No secret providers were registered in the secret store"
                : string.Concat(failures.Select(failure => $"{Environment.NewLine}\t- ({failure.providerName}): {failure.result.FailureMessage}"));

            var failureMessage = $"No registered secret provider could found secret '{secretName}': {messages}";
            var failureCauses = failures.Where(f => f.result.FailureCause != null).Select(f => f.result.FailureCause).ToArray();

            if (failureCauses.Length <= 0)
            {
                return SecretResult.Failure(failureMessage);
            }

            var failureCause = failureCauses.Length == 1
                ? failureCauses[0]
                : new AggregateException(failureCauses);

            _logger.LogError(failureCause, failureMessage);
            return SecretResult.Failure(failureMessage, failureCause);
        }

        private Dictionary<string, Lazy<ISecretProvider>> CreateGroupedSecretProviders(
            IEnumerable<SecretProviderRegistration> secretProvidersRegistrations,
            ILogger logger)
        {
            return secretProvidersRegistrations
                   .GroupBy(r => r.Options.ProviderName)
                   .ToDictionary(group => group.Key, group =>
                   {
                       return new Lazy<ISecretProvider>(() =>
                       {
                           if (group.Count() == 1)
                           {
                               var provider = group.Single();
                               return provider.SecretProvider;
                           }

                           return new CompositeSecretProvider(group.ToArray(), _options, logger);
                       });
                   });
        }
    }
}
