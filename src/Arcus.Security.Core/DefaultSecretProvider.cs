using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Primitives;

namespace Arcus.Security
{
    /// <summary>
    /// Represents the options to manipulate the behavior of 
    /// </summary>
    public class SecretOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether the secret retrieval is allowed to use a cached secret;
        /// if <c>false</c>, the secret provider will always retrieve the fresh secret from the underlying store.
        /// (Default: <c>true</c>)
        /// </summary>
        public bool UseCache { get; set; } = true;
    }

    internal sealed class SecretProviderRegistration : IDisposable
    {
        internal SecretProviderRegistration(ISecretProvider secretProvider, SecretProviderOptions options)
        {
            ArgumentNullException.ThrowIfNull(secretProvider);
            ArgumentNullException.ThrowIfNull(options);

            SecretProvider = secretProvider;
            Options = options;
        }

        internal ISecretProvider SecretProvider { get; }
        internal SecretProviderOptions Options { get; }

        public void Dispose()
        {
            if (SecretProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    /// <summary>
    /// Represents a provider that can retrieve secrets based on a given name.
    /// </summary>
    public interface ISecretProvider
    {
        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The </param>
        Task<SecretResult> GetSecretAsync(string secretName)
        {
            return Task.FromResult(GetSecret(secretName));
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName"></param>
        /// <returns></returns>
        SecretResult GetSecret(string secretName);
    }

    /// <summary>
    /// Represents the aggregated result of a secrets retrieval operation, which can either be successful or contain failure information.
    /// </summary>
    public class SecretsResult : IEnumerable<SecretResult>
    {
        private readonly IReadOnlyCollection<SecretResult> _secrets;
        private readonly string _failureMessage;
        private readonly Exception _failureCause;

        private SecretsResult(SecretResult[] secrets)
        {
            _secrets = secrets;
            IsSuccess = secrets.All(secret => secret.IsSuccess);

            (string FailureMessage, Exception FailureCause)[] failures =
                secrets.Where(s => !s.IsSuccess).Select(s => (s.FailureMessage, s.FailureCause)).ToArray();

            _failureMessage = string.Join(Environment.NewLine, failures.Select(f => f.FailureMessage));
            _failureCause = failures.Length > 0 ? new AggregateException(failures.Select(f => f.FailureCause)) : null;
        }

        /// <summary>
        /// Creates a <see cref="SecretsResult"/> instance with the given collection of secrets.
        /// </summary>
        public static SecretsResult Create(IEnumerable<SecretResult> secrets)
        {
            if (secrets is null)
            {
                throw new ArgumentNullException(nameof(secrets), "Requires a collection of secrets to be successful");
            }

            return new SecretsResult(secrets.ToArray());
        }

        /// <summary>
        /// Gets the boolean flag indicating whether the secrets retrieval was successful or not.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public string FailureMessage => !IsSuccess ? _failureMessage : throw new InvalidOperationException("Cannot get failure message as the secrets retrieval was successful");

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public Exception FailureCause => !IsSuccess ? _failureCause : throw new InvalidOperationException("Cannot get failure cause as the secrets retrieval was successful");

        /// <summary>
        /// Returns an enumerator that iterates through the collection.
        /// </summary>
        /// <returns>An enumerator that can be used to iterate through the collection.</returns>
        public IEnumerator<SecretResult> GetEnumerator()
        {
            return _secrets.GetEnumerator();
        }

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>An <see cref="IEnumerator" /> object that can be used to iterate through the collection.</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    /// <summary>
    /// Represents the result of a secret retrieval operation, which can either be successful or contain failure information.
    /// </summary>
    public class SecretResult
    {
        private readonly string _secretName, _secretValue, _secretVersion, _failureMessage;
        private readonly DateTimeOffset _expirationDate;
        private readonly Exception _failureCause;

        private SecretResult(string failureMessage, Exception failureCause)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(failureMessage);

            _failureMessage = failureMessage;
            _failureCause = failureCause;

            IsSuccess = false;
        }

        private SecretResult(string secretName, string secretValue, string secretVersion, DateTimeOffset expirationDate)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

            _secretName = secretName;
            _secretValue = secretValue;
            _secretVersion = secretVersion;
            _expirationDate = expirationDate;

            IsSuccess = true;
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        public static SecretResult Success(string secretName, string secretValue)
        {
            return new SecretResult(secretName, secretValue, secretVersion: null, DateTimeOffset.MaxValue);
        }

        /// <summary>
        /// Creates a successful <see cref="SecretResult"/> instance.
        /// </summary>
        public static SecretResult Success(string secretName, string secretValue, string secretVersion, DateTimeOffset expirationDate)
        {
            return new SecretResult(secretName, secretValue, secretVersion, expirationDate);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance with the given failure message.
        /// </summary>
        public static SecretResult Failure(string failureMessage)
        {
            return new SecretResult(failureMessage, null);
        }

        /// <summary>
        /// Creates a failed <see cref="SecretResult"/> instance with the given failure message and cause.
        /// </summary>
        public static SecretResult Failure(string failureMessage, Exception failureCause)
        {
            return new SecretResult(failureMessage, failureCause);
        }

        /// <summary>
        /// Gets the boolean flag indicating whether the secret retrieval was successful or not.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the secret value that was retrieved from the secret provider.
        /// </summary>
        public string Name => IsSuccess ? _secretName : throw new InvalidOperationException($"[Arcus] cannot get secret name as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the value of the secret that was retrieved from the secret provider.
        /// </summary>
        public string Value => IsSuccess ? _secretValue : throw new InvalidOperationException($"[Arcus] cannot get secret value as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the version of the secret that was retrieved from the secret provider.
        /// </summary>
        public string Version => IsSuccess ? _secretVersion : throw new InvalidOperationException($"[Arcus] cannot get secret version as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the expiration date of the secret that was retrieved from the secret provider.
        /// </summary>
        public DateTimeOffset Expiration => IsSuccess ? _expirationDate : throw new InvalidOperationException($"[Arcus] cannot get secret expiration date as the secret retrieval failed: {_failureMessage}", _failureCause);

        /// <summary>
        /// Gets the failure message that was returned when the secret retrieval failed.
        /// </summary>
        public string FailureMessage => !IsSuccess ? _failureMessage : throw new InvalidOperationException($"[Arcus] cannot get failure message as the secret retrieval was successful: {_secretName}");

        /// <summary>
        /// Gets the exception that was thrown when the secret retrieval failed.
        /// </summary>
        public Exception FailureCause => !IsSuccess ? _failureCause : throw new InvalidOperationException($"[Arcus] cannot get failure cause as the secret retrieval was successful: {_secretName}");

        /// <summary>
        /// Converts the <see cref="SecretResult"/> to a string representation, which is the secret value.
        /// </summary>
        public static implicit operator string(SecretResult result)
        {
            return result?.Value;
        }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        /// <returns>A string that represents the current object.</returns>
        public override string ToString()
        {
            return IsSuccess ? $"[Success]: {Name}" : $"[Failure]: {FailureMessage} {FailureCause}";
        }
    }

    /// <summary>
    /// Represents the central point of contact to retrieve secrets from registered <see cref="ISecretProvider"/>s in the user application.
    /// </summary>
    public interface ISecretStore : ISecretProvider, ISecretStoreContext
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <typeparam name="TProvider">The concrete type of the secret provider implementation.</typeparam>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the FQN (fully-qualified name) of the type in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        TProvider GetProvider<TProvider>(string providerName) where TProvider : ISecretProvider;

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The </param>
        /// <param name="configureOptions"></param>
        Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions);

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName"></param>
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions);
    }

    /// <summary>
    /// Represents the current user-configurable situation of an <see cref="ISecretStore"/> implementation,
    /// a.k.a. all extra options the user set during the secret store registration (like: <see cref="SecretStoreBuilder.UseCaching"/>).
    /// </summary>
    public interface ISecretStoreContext
    {
        /// <summary>
        /// Gets the service to interact with the possible configured cache on the secret store.
        /// </summary>
        SecretStoreCaching Cache { get; }
    }

    /// <summary>
    /// Represents the service to interact with the cache of the secret store.
    /// </summary>
    public class SecretStoreCaching
    {
        private IMemoryCache _cache = new NullMemoryCache();
        private MemoryCacheEntryOptions _cacheEntry = new();

        internal void SetDuration(TimeSpan duration)
        {
            _cache = new MemoryCache(new MemoryCacheOptions());
            _cacheEntry = new MemoryCacheEntryOptions().SetSlidingExpiration(duration);
        }

        internal bool TryGetCachedSecret(string secretName, SecretOptions secretOptions, out SecretResult secret)
        {
            if (secretOptions.UseCache)
            {
                return _cache.TryGetValue(secretName, out secret);
            }

            secret = null;
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretName"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public Task RefreshSecretAsync(string secretName, SecretResult result)
        {
            UpdateSecretInCache(secretName, result);
            return Task.CompletedTask;
        }

        internal void UpdateSecretInCache(string secretName, SecretResult result, SecretOptions options = null)
        {
            if (result.IsSuccess && (options is null || options.UseCache))
            {
                _cache.Set(secretName, result, _cacheEntry);
            }
        }

        /// <summary>
        /// Removes a secret from the cache on the secret provider,
        /// so that the next time this secret is retrieved, a fresh secret is provided from the registered <see cref="ISecretProvider"/>.
        /// </summary>
        public Task InvalidateSecretAsync(string secretName)
        {
            _cache.Remove(secretName);
            return Task.CompletedTask;
        }

        internal sealed class NullMemoryCache : IMemoryCache
        {
            public ICacheEntry CreateEntry(object key) => new NullCacheEntry();
            public void Remove(object key) { }
            public void Dispose() { }
            public bool TryGetValue(object key, out object value)
            {
                value = null;
                return false;
            }
        }

        internal sealed class NullCacheEntry : ICacheEntry
        {
            public object Key { get; }
            public object Value { get; set; }
            public DateTimeOffset? AbsoluteExpiration { get; set; }
            public TimeSpan? AbsoluteExpirationRelativeToNow { get; set; }
            public TimeSpan? SlidingExpiration { get; set; }
            public IList<IChangeToken> ExpirationTokens { get; }
            public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks { get; }
            public CacheItemPriority Priority { get; set; }
            public long? Size { get; set; }
            public void Dispose() { }
        }
    }

    /// <summary>
    /// Extension methods for the <see cref="ISecretStore"/> interface to retrieve a named <see cref="ISecretProvider"/> implementation.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class ISecretStoreExtensions
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="secretStore">The secret store to retrieve the provider from.</param>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the FQN (fully-qualified name) of the type in case none is provided.
        /// </param>
        /// <returns>The requested secret provider.</returns>
        public static ISecretProvider GetProvider(this ISecretStore secretStore, string providerName)
        {
            ArgumentNullException.ThrowIfNull(secretStore);
            return secretStore.GetProvider<ISecretProvider>(providerName);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="secretName"></param>
        /// <returns></returns>
        public static SecretResult GetSecret(this ISecretStore store, string secretName)
        {
            ArgumentNullException.ThrowIfNull(store);
            return store.GetSecret(secretName, configureOptions: null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="store"></param>
        /// <param name="secretName"></param>
        /// <returns></returns>
        public static Task<SecretResult> GetSecretAsync(this ISecretStore store, string secretName)
        {
            ArgumentNullException.ThrowIfNull(store);
            return store.GetSecretAsync(secretName, configureOptions: null);
        }
    }

    /// <summary>
    /// Represents the available options to configure the <see cref="ISecretProvider"/>.
    /// </summary>
    public class SecretProviderOptions
    {
        private readonly Collection<Func<string, string>> _secretNameMappers = [];
        private string _name;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretProviderOptions"/> class.
        /// </summary>
        /// <param name="secretProviderType">The type of the <see cref="ISecretProvider"/> implementation -- used to determine the <see cref="ProviderName"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderType"/> is <c>null</c>.</exception>
        public SecretProviderOptions(Type secretProviderType)
        {
            ArgumentNullException.ThrowIfNull(secretProviderType);
            ProviderName = secretProviderType.Name;
        }

        internal Func<string, string> SecretNameMapper => name => _secretNameMappers.Aggregate(name, (x, map) => map(x));

        /// <summary>
        /// Configures the secret provider to map the secret name before looking it up in the secret store.
        /// Multiple calls will be aggregated together.
        /// </summary>
        /// <param name="mutateSecretName"></param>
        public void MapSecretName(Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(mutateSecretName);
            _secretNameMappers.Add(mutateSecretName);
        }

        /// <summary>
        /// Gets or sets the name of the <see cref="ISecretProvider"/> to be registered in the secret store.
        /// </summary>
        /// <remarks>
        ///     When no name is provided by the user, it falls back on the type name of the registered <see cref="ISecretProvider"/>.
        /// </remarks>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string ProviderName
        {
            get => _name;
            set
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(value);
                _name = value;
            }
        }
    }
}
