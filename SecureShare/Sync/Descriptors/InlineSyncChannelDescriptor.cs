using System;
using System.Text.Json.Serialization;
using ProtoBuf;

namespace VaettirNet.SecureShare.Sync.Descriptors;

[ProtoContract]
public class InlineSyncChannelDescriptor : SyncChannelDescriptor
{
    [JsonIgnore]
    public override bool IsPersistentChannel => false;
    [JsonIgnore]
    public override bool IsOfflineAccessible => false;

    public required ReadOnlyMemory<byte> Data { get; init; }
}