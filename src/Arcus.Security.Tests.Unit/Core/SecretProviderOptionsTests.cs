using System;
using Xunit;

namespace Arcus.Security.Tests.Unit.Core
{
    public class SecretProviderOptionsTests
    {
        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("       ")]
        public void SetName_WithoutValue_Fails(string name)
        {
            // Arrange
            var options = new SecretProviderOptions(GetType());

            // Act / Assert
            Assert.ThrowsAny<ArgumentException>(() => options.Name = name);
        }
    }
}
