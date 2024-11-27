using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.TreeFormat;

[PackedBinarySerializable(IncludeNonPublic = true)]
public sealed class NodeRecord : ISignable
{
    [PackedBinaryConstructor]
    public NodeRecord(ReadOnlyMemory<byte> parent, NodeValue value)
    {
        Parent = parent;
        Value = value;
    }

    [PackedBinaryMember(1)]
    public ReadOnlyMemory<byte> Parent { get; }
    [PackedBinaryMember(2)]
    public NodeValue Value { get; }

    public bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        cb = 0;
        Span<byte> working = destination;
        if (!Parent.Span.TryCopyTo(working)) return false;
        working = working.Slice(Parent.Length);
        if (!Value.TryGetDataToSign(working, out int cbValue)) return false;
        cb = Parent.Length + cbValue;
        return true;
    }
}