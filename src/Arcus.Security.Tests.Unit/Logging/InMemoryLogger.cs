using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.Extensions.Logging;

namespace Arcus.Testing
{
    [Obsolete("Will be removed in v3.0 when we remove the hard-link with Arcus.Observability")]
    internal class InMemoryLogger : ILogger
    {
        private readonly Collection<string> _messages = [];
        public IReadOnlyCollection<string> Messages => _messages;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            _messages.Add(formatter(state, exception));
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return null;
        }
    }
}
