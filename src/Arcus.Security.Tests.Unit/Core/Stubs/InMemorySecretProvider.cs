﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;

namespace Arcus.Security.Tests.Unit.Core.Stubs
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides an in-memory storage of secrets by name.
    /// </summary>
    public class InMemorySecretProvider : ISecretProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        /// <param name="secretValueByName">The sequence of combinations of secret names and values.</param>
        public InMemorySecretProvider(params (string name, string value)[] secretValueByName)
        {
            Guard.NotNull(secretValueByName, "Secret name/value combinations cannot be 'null'");

            SecretValueByName = secretValueByName.ToDictionary(t => t.name, t => t.value);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemorySecretProvider"/> class.
        /// </summary>
        /// <param name="secretValueByName">The sequence of combinations of secret names and values.</param>
        public InMemorySecretProvider(IDictionary<string, string> secretValueByName)
        {
            Guard.NotNull(secretValueByName, "Secret name/value combinations cannot be 'null'");

            SecretValueByName = secretValueByName;
        }

        /// <summary>
        /// Gets the available stored secrets.
        /// </summary>
        protected IDictionary<string, string> SecretValueByName { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public virtual Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNull(secretName, "Secret name cannot be 'null'");

            if (SecretValueByName.TryGetValue(secretName, out string secretValue))
            {
                var secret = new Secret(secretValue, version: $"v-{Guid.NewGuid()}");
                return Task.FromResult(secret);
            }

            return Task.FromResult<Secret>(null);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public virtual async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNull(secretName, "Secret name cannot be 'null'");

            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }
    }
}
