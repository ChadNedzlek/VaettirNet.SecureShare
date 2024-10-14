using ProtoBuf;

namespace VaettirNet.SecureShare.Sync.Descriptors;

[ProtoContract]
[ProtoInclude(1, typeof(FileSyncChannelDescriptor))]
[ProtoInclude(1, typeof(TcpSyncChannelDescriptor))]
[ProtoInclude(1, typeof(InlineSyncChannelDescriptor))]
public abstract class SyncChannelDescriptor
{
    public abstract bool IsPersistentChannel { get; }
    public abstract bool IsOfflineAccessible { get; }
}