using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace TreeFormat;

[PackedBinarySerializable]
public sealed class NodeRecord
{
    public NodeRecord(ReadOnlyMemory<byte> parent, ReadOnlyMemory<byte> signature, NodeValue value)
    {
        Parent = parent;
        Signature = signature;
        Value = value;
    }

    public ReadOnlyMemory<byte> Parent { get; private init; }
    public ReadOnlyMemory<byte> Signature { get; private init; }
    public NodeValue Value { get; private init; }
}