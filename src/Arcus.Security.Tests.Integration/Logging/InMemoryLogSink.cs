using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Serilog.Core;
using Serilog.Events;

namespace Arcus.Security.Tests.Integration.Logging
{
    [Obsolete("Will be removed in v3.0 when we drop the Serilog dependency")]
    public class InMemoryLogSink : ILogEventSink
    {
        private Collection<LogEvent> _emits = [];

        public IReadOnlyCollection<LogEvent> CurrentLogEmits => _emits;

        public void Emit(LogEvent logEvent)
        {
            _emits.Add(logEvent);
        }
    }
}
