using System;
using System.Threading.Tasks;
using Arcus.Security.Tests.Core.Assertion;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.CommandLine
{
    public class SecretStoreBuilderExtensionsTests
    {
        [Fact]
        public async Task AddCommandLine_WithArguments_Succeeds()
        {
            // Arrange
            string secretName = "MySecret", expected = "P@ssw0rd";
            var arguments = new[] { $"--{secretName}={expected}" };
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddCommandLine(arguments));

            // Assert
            using (IHost host = builder.Build())
            {
                var provider = host.Services.GetRequiredService<ISecretProvider>();

                await AssertProvider.ContainsSecretAsync(provider, secretName, expected);
            }
        }

        [Fact]
        public void AddCommandLine_WithoutArguments_Fails()
        {
            // Arrange
            var builder = new HostBuilder();

            // Act
            builder.ConfigureSecretStore((config, stores) => stores.AddCommandLine(arguments: null));

            // Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.Build());
        }
    }
}
