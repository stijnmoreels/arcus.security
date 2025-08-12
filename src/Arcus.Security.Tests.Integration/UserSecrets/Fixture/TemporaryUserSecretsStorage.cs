using System;
using System.IO;
using System.Text;
using System.Text.Json.Nodes;
using Arcus.Security.Tests.Integration.UserSecrets.Fixture;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.Logging;

[assembly: UserSecretsId(TemporaryUserSecretsStorage.TestSecretsId)]

namespace Arcus.Security.Tests.Integration.UserSecrets.Fixture
{
    internal sealed class TemporaryUserSecretsStorage : IDisposable
    {
        public const string TestSecretsId = "d6076a6d3ab24c00b2511f10a56c68cc";

        private readonly FileInfo _userSecretsFile;
        private readonly DirectoryInfo _userSecretsDirectory;
        private readonly bool _createdByUs;
        private readonly ILogger _logger;

        private TemporaryUserSecretsStorage(
            FileInfo userSecretsFile,
            DirectoryInfo userSecretsDirectory,
            bool createdByUs,
            ILogger logger)
        {
            _userSecretsFile = userSecretsFile;
            _userSecretsDirectory = userSecretsDirectory;
            _createdByUs = createdByUs;
            _logger = logger;
        }

        public static TemporaryUserSecretsStorage CreateIfNotExists(ILogger logger)
        {
            string secretsFilePath = PathHelper.GetSecretsPathFromSecretsId(TestSecretsId);
            var secretsFile = new FileInfo(secretsFilePath);
            string secretsDirPath = Path.GetDirectoryName(secretsFilePath);

            var userSecretsDirectory = new DirectoryInfo(secretsDirPath!);
            if (userSecretsDirectory.Exists)
            {
                logger.LogTrace("[Test:Setup] Use already existing UserSecrets local directory at '{DirectoryPath}'", userSecretsDirectory.FullName);
                return new TemporaryUserSecretsStorage(secretsFile, userSecretsDirectory, createdByUs: false, logger);
            }

            logger.LogTrace("[Test:Setup] Create new UserSecrets local directory at '{DirectoryPath}'", userSecretsDirectory.FullName);
            userSecretsDirectory.Create();

            return new TemporaryUserSecretsStorage(secretsFile, userSecretsDirectory, createdByUs: true, logger);
        }

        public void AddUserSecret(string secretName, string secretValue)
        {
            _logger.LogTrace("[Test] Add new UserSecret '{Name}' to local storage at '{FilePath}'", secretName, _userSecretsFile.FullName);

            string currentJsonContents = File.ReadAllText(_userSecretsFile.FullName);
            JsonObject currentJson = JsonNode.Parse(currentJsonContents)!.AsObject();
            currentJson[secretName] = secretValue;

            File.WriteAllText(_userSecretsFile.FullName, currentJson.ToString(), Encoding.UTF8);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (_createdByUs)
            {
                if (_userSecretsDirectory.Exists)
                {
                    _logger.LogTrace("[Test:Teardown] Delete UserSecrets local directory at '{DirectoryPath}'", _userSecretsDirectory.FullName);
                    _userSecretsDirectory.Delete(recursive: true);
                }
                else
                {
                    _logger.LogTrace("[Test:Teardown] UserSecrets local directory already deleted at '{DirectoryPath}'", _userSecretsDirectory.FullName);
                }
            }
        }
    }
}
