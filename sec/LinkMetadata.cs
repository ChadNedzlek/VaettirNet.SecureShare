using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace sec;

[ProtoContract(SkipConstructor = true)]
public class LinkMetadata : FullSerializable<LinkMetadata>
{
    [ProtoMember(1)]
    public DateTimeOffset Created { get; private set; }

    public LinkMetadata()
    {
        Created = DateTimeOffset.Now;
    }
}