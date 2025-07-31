using System;
using System.IO;
using System.Reflection;
using Arcus.Security;
using Arcus.Security.Providers.UserSecrets;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.FileProviders;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// <see cref="SecretStoreBuilder"/> extensions for adding user secrets to the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        private const string SecretsFileName = "secrets.json";

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets<T>(this SecretStoreBuilder builder) where T : class
        {
            return AddUserSecrets<T>(builder, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configureOptions">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            Action<SecretProviderOptions> configureOptions) where T : class
        {
            Assembly assembly = typeof(T).GetTypeInfo().Assembly;
            return AddUserSecrets(builder, assembly, configureOptions);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="assembly"/> does not have a valid <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            Assembly assembly)
        {
            return AddUserSecrets(builder, assembly, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <param name="configureOptions">The additional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="assembly"/> does not have a valid <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            Assembly assembly,
            Action<SecretProviderOptions> configureOptions)
        {
            string userSecretsId = GetUserSecretsIdFromTypeAssembly(assembly);
            return AddUserSecrets(builder, userSecretsId, configureOptions);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            string userSecretsId)
        {
            return AddUserSecrets(builder, userSecretsId, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <param name="configureOptions">The optional options to configure the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            string userSecretsId,
            Action<SecretProviderOptions> configureOptions)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(userSecretsId);

            return builder.AddProvider((_, options) =>
            {
                string directoryPath = GetUserSecretsDirectoryPath(userSecretsId);
                JsonConfigurationSource source = CreateJsonFileSource(directoryPath);

                var provider = new JsonConfigurationProvider(source);
                provider.Load();

                return new UserSecretsSecretProvider(provider, options);

            }, configureOptions);

        }

        private static string GetUserSecretsIdFromTypeAssembly(Assembly assembly)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            var attribute = assembly.GetCustomAttribute<UserSecretsIdAttribute>();
            if (attribute is null)
            {
                string assemblyName = assembly.GetName().Name;
                throw new InvalidOperationException(
                    $"Could not find '{nameof(UserSecretsIdAttribute)}' on assembly '{assemblyName}'. "
                    + $"Check that the project for '{assemblyName}' has set the 'UserSecretsId' build property.");
            }

            return attribute.UserSecretsId;
        }

        private static string GetUserSecretsDirectoryPath(string usersSecretsId)
        {
            if (string.IsNullOrWhiteSpace(usersSecretsId))
            {
                throw new ArgumentException("Requires a non-blank user secret ID to determine the local path of the users secrets", nameof(usersSecretsId));
            }

            string secretPath = PathHelper.GetSecretsPathFromSecretsId(usersSecretsId);
            string directoryPath = Path.GetDirectoryName(secretPath);

            return directoryPath;
        }

        private static JsonConfigurationSource CreateJsonFileSource(string directoryPath)
        {
            IFileProvider fileProvider = null;
            if (Directory.Exists(directoryPath))
            {
                fileProvider = new PhysicalFileProvider(directoryPath);
            }

            var source = new JsonConfigurationSource
            {
                FileProvider = fileProvider,
                Path = SecretsFileName,
                Optional = false
            };

            source.ResolveFileProvider();
            if (source.FileProvider == null)
            {
                source.FileProvider = new PhysicalFileProvider(AppContext.BaseDirectory ?? String.Empty);
            }

            return source;
        }
    }
}
