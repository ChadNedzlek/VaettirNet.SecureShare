using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.CommandLine;

[PackedBinarySerializable]
public class LinkMetadata : FullSerializable<LinkMetadata>
{
    [PackedBinaryMember(1)]
    public DateTimeOffset Created { get; private set; }

    public LinkMetadata()
    {
        Created = DateTimeOffset.Now;
    }
}