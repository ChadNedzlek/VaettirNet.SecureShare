using ProtoBuf;

namespace VaettirNet.SecureShare.Sync.Descriptors;

[ProtoContract]
public class FileSyncChannelDescriptor : SyncChannelDescriptor
{
    public override bool IsPersistentChannel => true;
    public override bool IsOfflineAccessible => true;

    public required string Path { get; init; }
}