using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ISecretStore
    {
        private readonly IReadOnlyCollection<SecretProviderRegistration> _secretProviders;
        private readonly Dictionary<string, Lazy<ISecretProvider>> _secretProvidersByName;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderRegistrations">The sequence of all available registered secret provider registrations.</param>
        /// <param name="logger">The logger instance to write diagnostic messages during the retrieval of secrets via the registered <paramref name="secretProviderRegistrations"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderRegistrations"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderRegistrations"/> contains any <c>null</c> values.</exception>
        internal CompositeSecretProvider(
            IReadOnlyCollection<SecretProviderRegistration> secretProviderRegistrations,
            ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(secretProviderRegistrations);

            var registrations = secretProviderRegistrations.Where(r => r != null).ToArray();

            _secretProviders = registrations;
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;

            _secretProvidersByName = CreateGroupedSecretProviders(registrations, logger);
        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <typeparam name="TProvider">The concrete type of the secret provider implementation.</typeparam>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the FQN (fully-qualified name) of the type in case none is provided.
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
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        public SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions)
        {
            return GetSecretCoreAsync(secretName, secretProvider =>
            {
                return Task.FromResult(secretProvider.GetSecret(secretName, configureOptions));

            }).Result;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The </param>
        /// <param name="configureOptions"></param>
        public Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions)
        {
            return GetSecretCoreAsync(secretName, secretProvider => secretProvider.GetSecretAsync(secretName, configureOptions));
        }

        private async Task<SecretResult> GetSecretCoreAsync(
            string secretName,
            Func<ISecretProvider, Task<SecretResult>> getSecretAsync)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            var failures = new Collection<SecretResult>();
            foreach (SecretProviderRegistration source in _secretProviders)
            {
                try
                {
                    SecretResult result = await getSecretAsync(source.SecretProvider);
                    if (result is null)
                    {
                        _logger.LogTrace("Secret provider '{SecretProviderName}' doesn't contain secret with name {SecretName} as it returned 'null'", source.Options.Name, secretName);
                        continue;
                    }

                    if (result.IsSuccess)
                    {
                        return result;
                    }

                    failures.Add(result);
                }
                catch (Exception exception)
                {
                    failures.Add(SecretResult.Failure($"Secret provider '{source.Options.Name}' failed to find secret '{secretName}' due to an unexpected failure", exception));
                    _logger.LogTrace(exception, "Secret provider '{SecretProviderName}' doesn't contain secret with name {SecretName}", source.Options.Name, secretName);
                }
            }

            SecretResult noneFoundFailure = CreateSecretResultNoneFoundFailure(secretName, failures);
            return noneFoundFailure;
        }

        private static SecretResult CreateSecretResultNoneFoundFailure(string secretName, Collection<SecretResult> failures)
        {
            string messages = failures.Count == 0
                ? "No secret providers were registered in the secret store"
                : string.Concat(failures.Select(failure => $"{Environment.NewLine}- {failure.FailureMessage}"));

            var failureMessage = $"No registered secret provider could found secret '{secretName}': {messages}";
            var failureCauses = failures.Where(f => f.FailureCause != null).Select(f => f.FailureCause).ToArray();

            if (failureCauses.Length <= 0)
            {
                return SecretResult.Failure(failureMessage);
            }

            return failureCauses.Length == 1
                ? SecretResult.Failure(failureMessage, failureCauses[0])
                : SecretResult.Failure(failureMessage, new AggregateException(failureCauses));
        }

        private static Dictionary<string, Lazy<ISecretProvider>> CreateGroupedSecretProviders(
            IEnumerable<SecretProviderRegistration> secretProvidersRegistrations,
            ILogger logger)
        {
            return secretProvidersRegistrations
                   .GroupBy(r => r.Options.Name)
                   .ToDictionary(group => group.Key, group =>
                   {
                       return new Lazy<ISecretProvider>(() =>
                       {
                           if (group.Count() == 1)
                           {
                               var provider = group.Single();
                               return provider.SecretProvider;
                           }

                           return new CompositeSecretProvider(group.ToArray(), logger);
                       });
                   });
        }
    }
}
