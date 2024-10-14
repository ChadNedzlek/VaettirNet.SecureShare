using System.Text.Json.Serialization;
using ProtoBuf;

namespace VaettirNet.SecureShare.Sync.Descriptors;

[ProtoContract]
public class TcpSyncChannelDescriptor : SyncChannelDescriptor
{
    [JsonIgnore]
    public override bool IsPersistentChannel => false;
    [JsonIgnore]
    public override bool IsOfflineAccessible => false;

    public required string Host { get; init; }
    public required int Port { get; init; }
}