using System;
using Microsoft.Extensions.Logging;

namespace Arcus.Testing
{
    [Obsolete("Will be removed in v3.0 when we removed the hard-link with Arcus.Observability")]
    internal class CustomLoggerProvider : ILoggerProvider
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CustomLoggerProvider"/> class.
        /// </summary>
        public CustomLoggerProvider(ILogger logger)
        {
            _logger = logger;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return _logger;
        }

        public void Dispose()
        {
        }
    }
}
