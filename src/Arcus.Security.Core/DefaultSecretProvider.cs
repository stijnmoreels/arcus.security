using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
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

    internal class SecretProviderRegistration
    {
        internal SecretProviderRegistration(ISecretProvider secretProvider, SecretProviderOptions options = null)
        {
            ArgumentNullException.ThrowIfNull(secretProvider);
            SecretProvider = secretProvider;
            Options = options ?? new SecretProviderOptions(secretProvider.GetType());
        }

        internal ISecretProvider SecretProvider { get; }
        internal SecretProviderOptions Options { get; }
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
        /// <param name="configureOptions"></param>
        Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions)
        {
            return Task.FromResult(GetSecret(secretName, configureOptions));
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName"></param>
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions);
    }

    /// <summary>
    /// 
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class ISecretProviderExtensions
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretProvider"></param>
        /// <param name="secretName"></param>
        /// <returns></returns>
        public static async Task<SecretResult> GetSecretAsync(this ISecretProvider secretProvider, string secretName)
        {
            return await secretProvider.GetSecretAsync(secretName, configureOptions: null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretProvider"></param>
        /// <param name="secretName"></param>
        /// <returns></returns>
        public static SecretResult GetSecret(this ISecretProvider secretProvider, string secretName)
        {
            return secretProvider.GetSecret(secretName, configureOptions: null);
        }
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
            _failureMessage = failureMessage ?? throw new ArgumentNullException(nameof(failureMessage));
            _failureCause = failureCause ?? throw new ArgumentNullException(nameof(failureCause));
            IsSuccess = false;
        }

        private SecretResult(string secretName, string secretValue, string secretVersion, DateTimeOffset expirationDate)
        {
            _secretName = secretName ?? throw new ArgumentNullException(nameof(secretName));
            _secretValue = secretValue ?? throw new ArgumentNullException(nameof(secretValue));
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
    public interface ISecretStore : ISecretProvider
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
    }

    /// <summary>
    /// Represents the available options to configure the <see cref="ISecretProvider"/>.
    /// </summary>
    public class SecretProviderOptions
    {
        private readonly Collection<Func<string, string>> _secretNameMappers = [];
        private string _name;
        private IMemoryCache _cache = new NullMemoryCache();

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretProviderOptions"/> class.
        /// </summary>
        public SecretProviderOptions(Type secretProviderType)
        {
            ArgumentNullException.ThrowIfNull(secretProviderType);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretProviderType.Name);

            Name = secretProviderType.Name;
        }

        /// <summary>
        /// Gets or sets the memory cache to use for caching secrets.
        /// </summary>
        internal IMemoryCache Cache
        {
            get => _cache;
            set
            {
                ArgumentNullException.ThrowIfNull(value);
                _cache = value;
            }
        }

        internal Func<string, string> SecretNameMapper => name => _secretNameMappers.Aggregate(name, (x, map) => map(x));

        internal MemoryCacheEntryOptions CacheEntry { get; set; } = new();

        /// <summary>
        /// Configures the secret provider to use caching with a sliding expiration <paramref name="duration"/>.
        /// </summary>
        /// <param name="duration">The expiration time when the secret should be invalidated in the cache.</param>
        public void UseCaching(TimeSpan duration)
        {
            Cache = new MemoryCache(new MemoryCacheOptions());
            CacheEntry = new MemoryCacheEntryOptions().SetSlidingExpiration(duration);
        }

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
        /// <exception cref="ArgumentException">Thrown when the <paramref name="value"/> is blank.</exception>
        public string Name
        {
            get => _name;
            set
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(value);
                _name = value;
            }
        }

        private sealed class NullMemoryCache : IMemoryCache
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

        private sealed class NullCacheEntry : ICacheEntry
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
    /// Represents a kickstart implementation of an <see cref="ISecretProvider"/>
    /// with infrastructure boilerplate code embedded.
    /// </summary>
    public abstract class DefaultSecretProvider : ISecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultSecretProvider"/> class.
        /// </summary>
        protected DefaultSecretProvider(SecretProviderOptions options)
        {
            ProviderOptions = options ?? new SecretProviderOptions(GetType());
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultSecretProvider"/> class.
        /// </summary>
        protected DefaultSecretProvider()
        {
            ProviderOptions = new SecretProviderOptions(GetType());
        }

        internal SecretProviderOptions ProviderOptions { get; }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        public virtual SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions)
        {
            return GetOrAddSecretToCacheAsync(secretName, configureOptions, name =>
            {
                return Task.FromResult(GetSecret(name));

            }).Result;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected abstract SecretResult GetSecret(string secretName);

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        /// <param name="configureOptions"></param>
        public async Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions)
        {
            return await GetOrAddSecretToCacheAsync(secretName, configureOptions, GetSecretAsync);
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected virtual Task<SecretResult> GetSecretAsync(string secretName)
        {
            return Task.FromResult(GetSecret(secretName));
        }

        private async Task<SecretResult> GetOrAddSecretToCacheAsync(
            string secretName,
            Action<SecretOptions> configureOptions,
            Func<string, Task<SecretResult>> getSecretAsync)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            var options = new SecretOptions();
            configureOptions?.Invoke(options);

            secretName = ProviderOptions.SecretNameMapper(secretName);

            if (TryGetCachedSecret(secretName, options, out SecretResult cachedSecret))
            {
                return cachedSecret;
            }

            SecretResult secret = await getSecretAsync(secretName);
            if (options.UseCache)
            {
                UpdateSecretInCache(secretName, secret);
            }

            return secret;
        }

        private bool TryGetCachedSecret(string secretName, SecretOptions secretOptions, out SecretResult secret)
        {
            if (secretOptions.UseCache)
            {
                return ProviderOptions.Cache.TryGetValue(secretName, out secret);
            }

            secret = null;
            return false;
        }

        /// <summary>
        /// Updates the secret in the cache with the given secret name and value.
        /// </summary>
        protected void UpdateSecretInCache(string secretName, SecretResult secret)
        {
            if (secret.IsSuccess)
            {
                ProviderOptions.Cache.Set(secretName, secret, ProviderOptions.CacheEntry);
            }
        }
    }
}
