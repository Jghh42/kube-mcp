using System.Collections.Concurrent;
using KubeMcp.Audit;
using Microsoft.Extensions.Logging;

namespace KubeMcp.Tests;

internal sealed class CapturingAuditLogProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<AuditLoggerTests.LogEntry> entries = new();

    public IReadOnlyList<AuditLoggerTests.LogEntry> Snapshot() => entries.ToArray();

    public ILogger CreateLogger(string categoryName) =>
        categoryName == typeof(AuditLogger).FullName
            ? new CapturingLogger(entries)
            : Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

    public void Dispose()
    {
    }

    public async Task<AuditLoggerTests.LogEntry> WaitForCategoryAsync(string category)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            var found = entries.FirstOrDefault(entry =>
                entry.Properties.TryGetValue("Category", out var value) &&
                string.Equals(value as string, category, StringComparison.Ordinal));
            if (found is not null)
            {
                return found;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException($"Audit category {category} was not logged.");
    }

    private sealed class CapturingLogger(ConcurrentQueue<AuditLoggerTests.LogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = ((IEnumerable<KeyValuePair<string, object?>>)state!)
                .Where(property => property.Key != "{OriginalFormat}")
                .ToDictionary(property => property.Key, property => property.Value);
            entries.Enqueue(new AuditLoggerTests.LogEntry(
                logLevel,
                eventId,
                properties,
                formatter(state, exception),
                exception));
        }
    }
}
