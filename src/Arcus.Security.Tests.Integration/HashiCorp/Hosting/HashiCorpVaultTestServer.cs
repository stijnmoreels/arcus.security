using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Arcus.Security.Providers.HashiCorp;
using Arcus.Security.Tests.Integration.HashiCorp.Mounting;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Vault;
using Vault.Endpoints;
using Vault.Endpoints.Sys;
using Vault.Models.Auth.UserPass;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines.KeyValue.V1;
using VaultSharp.V1.SecretsEngines.KeyValue.V2;
using MountInfo = Arcus.Security.Tests.Integration.HashiCorp.Mounting.MountInfo;
using VaultClient = Vault.VaultClient;

namespace Arcus.Security.Tests.Integration.HashiCorp.Hosting
{
    /// <summary>
    /// Represents a HashiCorp Vault instance running in 'dev server' mode.
    /// </summary>
    public sealed class HashiCorpVaultTestServer : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly string _rootToken;
        private readonly VaultSharp.VaultClient _apiClient;
        private readonly ISysEndpoint _systemEndpoint;
        private readonly IEndpoint _authenticationEndpoint;
        private readonly ILogger _logger;

        private static readonly Faker Bogus = new();

        private HashiCorpVaultTestServer(Process process, string rootToken, string listenAddress, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(process);
            ArgumentException.ThrowIfNullOrWhiteSpace(rootToken);
            ArgumentException.ThrowIfNullOrWhiteSpace(listenAddress);

            _process = process;
            _rootToken = rootToken;
            _logger = logger ?? NullLogger.Instance;

            ListenAddress = new UriBuilder(listenAddress).Uri;
            var client = new VaultClient(ListenAddress, rootToken);
            _systemEndpoint = client.Sys;
            _authenticationEndpoint = client.Auth;

            var settings = new VaultClientSettings(ListenAddress.ToString(), new TokenAuthMethodInfo(rootToken));
            _apiClient = new VaultSharp.VaultClient(settings);
        }

        /// <summary>
        /// Gets the URI where the HashiCorp Vault test server is listening on.
        /// </summary>
        public Uri ListenAddress { get; }

        public VaultClientSettings Settings => _apiClient.Settings;

        public string CustomMountPoint { get; } = Bogus.Lorem.Word().OrNull(Bogus);

        public VaultKeyValueSecretEngineVersion EngineVersion { get; set; } = Bogus.PickRandom<VaultKeyValueSecretEngineVersion>();

        /// <summary>
        /// Gets the KeyValue V2 secret engine to control the secret store in the HashiCorp Vault.
        /// </summary>
        public IKeyValueSecretsEngineV1 KeyValueV1 => _apiClient.V1.Secrets.KeyValue.V1;

        /// <summary>
        /// Gets the KeyValue V2 secret engine to control the secret store in the HashiCorp Vault.
        /// </summary>
        public IKeyValueSecretsEngineV2 KeyValueV2 => _apiClient.V1.Secrets.KeyValue.V2;

        public async Task<string> StoreSecretAsync(string secretName, string secretValue)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

            string path = Guid.NewGuid().ToString();
            Func<string, string, Task> writeSecretAsync = EngineVersion switch
            {
                VaultKeyValueSecretEngineVersion.V1 => (name, value) => KeyValueV1.WriteSecretAsync(path, new Dictionary<string, object> { [name] = value }, mountPoint: CustomMountPoint),
                VaultKeyValueSecretEngineVersion.V2 => (name, value) => KeyValueV2.WriteSecretAsync(path, new Dictionary<string, string> { [name] = value }, mountPoint: CustomMountPoint),
            };

            _logger.LogTrace("[Test] Store secret '{SecretName}' in HashiCorp Vault at '{Path}'", secretName, path);
            await writeSecretAsync(secretName, secretValue);

            return path;
        }

        /// <summary>
        /// Starts a new instance of the <see cref="HashiCorpVaultTestServer"/> using the 'dev server' settings, meaning the Vault will run fully in-memory.
        /// </summary>
        /// <param name="configuration">The configuration instance to retrieve the HashiCorp installation folder ('Arcus.HashiCorp.VaultBin').</param>
        /// <param name="logger">The instance to log diagnostic trace messages during the lifetime of the test server.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configuration"/> or <paramref name="logger"/> is <c>null</c>.</exception>
        public static async Task<HashiCorpVaultTestServer> StartServerAsync(TestConfig configuration, ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(configuration);

            var rootToken = Guid.NewGuid().ToString();
            int port = GetRandomUnusedPort();
            string listenAddress = $"127.0.0.1:{port}";

            Process process = CreateHashiCorpVaultExecutable(configuration, rootToken, listenAddress);
            var server = new HashiCorpVaultTestServer(process, rootToken, listenAddress, logger);

            try
            {
                await server.StartHashiCorpVaultAsync();
            }
            catch (Exception exception)
            {
                throw new CouldNotStartHashiCorpVaultException(
                    "[Test:Setup] An unexpected problem occurred while trying to start the HashiCorp Vault", exception);
            }
            finally
            {
                process.Dispose();
            }

            await InitializeUserPassAuthenticationAsync(configuration, server);
            return server;
        }

        private static Process CreateHashiCorpVaultExecutable(TestConfig configuration, string rootToken, string listenAddress)
        {
            string vaultArgs = string.Join(" ",
                "server", "-dev", $"-dev-root-token-id={rootToken}", $"-dev-listen-address={listenAddress}");

            FileInfo hashiCorpVaultBin = configuration.GetHashiCorpVaultBin();
            var process = new Process
            {
                StartInfo = new ProcessStartInfo(hashiCorpVaultBin.FullName, vaultArgs)
                {
                    WorkingDirectory = Directory.GetCurrentDirectory(),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    EnvironmentVariables = { ["HOME"] = Directory.GetCurrentDirectory() }
                }
            };

            return process;
        }

        private static async Task InitializeUserPassAuthenticationAsync(TestConfig configuration, HashiCorpVaultTestServer server)
        {
            if (server.CustomMountPoint != null)
            {
                await server.MountKeyValueAsync(server.CustomMountPoint, server.EngineVersion);
            }

            const string policyName = "my-policy";
            const string defaultDevMountPoint = "secret";

            await server.AddPolicyAsync(policyName, server.CustomMountPoint ?? defaultDevMountPoint, ["read"]);
            await server.EnableAuthenticationTypeAsync(AuthMethodDefaultPaths.UserPass, "Authenticating with username and password");
            await server.AddUserPassUserAsync(
                configuration["Arcus:HashiCorp:UserPass:UserName"],
                configuration["Arcus:HashiCorp:UserPass:Password"],
                policyName);
        }

        private static int GetRandomUnusedPort()
        {
            var listener = new TcpListener(IPAddress.Any, 0);
            listener.Start();
            int port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return port;
        }

        private async Task StartHashiCorpVaultAsync()
        {
            _logger.LogTrace("[Test:Setup] Starting HashiCorp Vault at '{listenAddress}'...", ListenAddress);

            if (!_process.Start())
            {
                throw new CouldNotStartHashiCorpVaultException(
                    $"Vault process did not start correctly, exit code: {_process.ExitCode}");
            }

            var isStarted = false;

            string line = await _process.StandardOutput.ReadLineAsync();
            while (line != null)
            {
                _logger.LogTrace(line);
                if (line?.StartsWith("==> Vault server started!") == true)
                {
                    isStarted = true;
                    break;
                }

                line = await _process.StandardOutput.ReadLineAsync();
            }

            if (!isStarted)
            {
                throw new CouldNotStartHashiCorpVaultException(
                    "Vault process wasn't configured correctly and could therefore not be started successfully");
            }

            _logger.LogInformation("[Test:Setup] HashiCorp Vault started at '{ListenAddress}'", ListenAddress);
        }

        private async Task MountKeyValueAsync(string path, VaultKeyValueSecretEngineVersion version)
        {
            var content = new MountInfo
            {
                Type = "kv",
                Description = "KeyValue v1 secret engine",
                Options = new MountOptions { Version = ((int) version).ToString() }
            };

            var http = new VaultHttpClient();
            var uri = new Uri(ListenAddress, "/v1/sys/mounts/" + path);
            await http.PostVoid(uri, content, _rootToken, CancellationToken.None);
        }

        private async Task AddPolicyAsync(string name, string path, string[] capabilities)
        {
            string joinedCapabilities = string.Join(", ", capabilities.Select(c => $"\"{c}\""));
            string rules = $"path \"{path}/*\" {{  capabilities = [ {joinedCapabilities} ]}}";

            await _systemEndpoint.PutPolicy(name, rules);
        }

        private async Task EnableAuthenticationTypeAsync(string type, string description)
        {
            await _systemEndpoint.EnableAuth(path: type, authType: type, description: description);
        }

        private async Task AddUserPassUserAsync(string username, string password, string policyName)
        {
            await _authenticationEndpoint.Write($"/userpass/users/{username}", new UsersRequest
            {
                Password = password,
                Policies = [policyName]
            });
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources asynchronously.
        /// </summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public async ValueTask DisposeAsync()
        {
            await using var disposables = new DisposableCollection(_logger);

            disposables.Add(AsyncDisposable.Create(async () =>
            {
                _logger.LogTrace("[Test:Teardown] Stopping HashiCorp Vault at '{ListenAddress}'...", ListenAddress);
                await Poll.Target(StopHashiCorpVault)
                          .Every(TimeSpan.FromSeconds(1))
                          .Timeout(TimeSpan.FromSeconds(30));
            }));
        }

        private void StopHashiCorpVault()
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }

            _process.Dispose();
        }
    }
}
