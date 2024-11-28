using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

[PackedBinarySerializable(IncludeNonPublic = true)]
public sealed class NodeRecord : ISignable
{
    [PackedBinaryConstructor]
    public NodeRecord(NodeValue value, params IEnumerable<ReadOnlyMemory<byte>> parentSignatures)
    {
        ParentSignatures = parentSignatures.ToImmutableArray();
        Value = value;
    }

    [PackedBinaryMember(1)]
    public ImmutableArray<ReadOnlyMemory<byte>> ParentSignatures { get; }

    [PackedBinaryMember(2)]
    public NodeValue Value { get; }

    public bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        cb = 0;
        Span<byte> working = destination;
        BinaryPrimitives.WriteInt32BigEndian(destination, ParentSignatures.Length);
        working = working.Slice(4);
        cb += 4;
        foreach (ReadOnlyMemory<byte> parent in ParentSignatures)
        {
            if (!parent.Span.TryCopyTo(working)) return false;
            cb += parent.Span.Length;
            working = working.Slice(parent.Span.Length);
        }

        if (!Value.TryGetDataToSign(working, out int cbValue)) return false;

        cb += cbValue;
        return true;
    }

    public override string ToString()
    {
        return $"[{ParentSignatures.Length}] = {Value}";
    }
}