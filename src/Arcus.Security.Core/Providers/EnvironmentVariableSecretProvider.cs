using System;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents the options to configure the <see cref="EnvironmentVariableSecretProvider"/> implementation.
    /// </summary>
    public class EnvironmentVariableSecretProviderOptions : SecretProviderOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProviderOptions"/> class.
        /// </summary>
        public EnvironmentVariableSecretProviderOptions() : base(typeof(EnvironmentVariableSecretProvider))
        {
        }

        /// <summary>
        /// Gets or sets the target on which the environment variables should be retrieved.
        /// </summary>
        public EnvironmentVariableTarget Target { get; set; } = EnvironmentVariableTarget.Process;

        /// <summary>
        /// Gets or sets the optional prefix which will be prepended to the secret name when retrieving environment variables.
        /// </summary>
        public string Prefix { get; set; }
    }

    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that retrieves secrets from the environment.
    /// </summary>
    public class EnvironmentVariableSecretProvider : DefaultSecretProvider
    {
        private readonly EnvironmentVariableTarget _target;
        private readonly string _prefix;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnvironmentVariableSecretProvider"/> class.
        /// </summary>
        public EnvironmentVariableSecretProvider(EnvironmentVariableSecretProviderOptions options) : base(options)
        {
            _target = options.Target;
            _prefix = options.Prefix;
        }

        /// <summary>
        /// Gets a stored secret by its name.
        /// </summary>
        /// <param name="secretName">The name of the secret to retrieve.</param>
        protected override SecretResult GetSecret(string secretName)
        {
            string environmentVariable = Environment.GetEnvironmentVariable(_prefix + secretName, _target);
            return environmentVariable is null
                ? SecretResult.Failure($"No secret found in environment variable for '{_prefix}{secretName}'")
                : SecretResult.Success(secretName, environmentVariable);
        }
    }
}
