using System;
using Arcus.Security.Core.Providers;
using Arcus.Security.Tests.Unit.Core.Stubs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretStoreBuilderTests
    {
        [Fact]
        public void AddProvider_WithoutSecretProvider_Throws()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new SecretStoreBuilder(services);

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => builder.AddProvider<InMemorySecretProvider>(secretProvider: null));
            Assert.ThrowsAny<ArgumentException>(() => builder.AddProvider<InMemorySecretProvider>(implementationFactory: null, configureOptions: _ => { }));
            Assert.ThrowsAny<ArgumentException>(() => builder.AddProvider<EnvironmentVariableSecretProvider, EnvironmentVariableSecretProviderOptions>(
                implementationFactory: null,
                configureOptions: _ => { }));
        }
    }
}
