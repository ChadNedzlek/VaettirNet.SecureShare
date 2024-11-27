using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.TreeFormat;

[PackedBinarySerializable]
public abstract class NodeValue : ISignable
{
    public abstract bool TryGetDataToSign(Span<byte> destination, out int cb);
}