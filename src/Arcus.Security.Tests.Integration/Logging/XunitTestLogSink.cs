using System;
using Arcus.Testing;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Arcus.Security.Tests.Integration.Logging
{
    [Obsolete("Will be removed in v3.0 when we drop the Serilog dependency")]
    internal class XunitTestLogSink : ILogEventSink
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="XunitTestLogSink"/> class.
        /// </summary>
        public XunitTestLogSink(ILogger logger)
        {
            _logger = logger;
        }

        public void Emit(LogEvent logEvent)
        {
            _logger.Log((LogLevel) (int) logEvent.Level, logEvent.MessageTemplate.Text, logEvent.MessageTemplate.Tokens);
        }
    }

    internal static class XunitTestLogSinkExtensions
    {
        [Obsolete("Will be removed in v3.0 when we drop the Serilog dependency")]
        public static LoggerConfiguration XunitTestLogging(this LoggerSinkConfiguration loggerConfiguration, ITestOutputHelper outputWriter)
        {
            return loggerConfiguration.Sink(new XunitTestLogSink(new XunitTestLogger(outputWriter)));
        }
    }
}
