using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace TreeFormat;

[PackedBinarySerializable(IncludeNonPublic = true)]
public sealed class NodeRecord
{
    public NodeRecord(ReadOnlyMemory<byte> parent, ReadOnlyMemory<byte> signature, NodeValue value)
    {
        Parent = parent;
        Signature = signature;
        Value = value;
    }

    [PackedBinaryMember(1)]
    public ReadOnlyMemory<byte> Parent { get; private init; }
    [PackedBinaryMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private init; }
    [PackedBinaryMember(3)]
    public NodeValue Value { get; private init; }
}