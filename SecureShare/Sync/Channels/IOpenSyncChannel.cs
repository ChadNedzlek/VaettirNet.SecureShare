using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VaettirNet.SecureShare.Sync.Channels;

public interface IOpenSyncChannel : IDisposable
{
    IAsyncEnumerable<SyncMessage> ListenForMessagesAsync(CancellationToken cancellationToken);
    Task<SyncMessage?> SendMessageAsync(SyncMessage message, bool waitForResponse, CancellationToken cancellationToken);
}