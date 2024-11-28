using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

[PackedBinarySerializable]
public abstract class NodeValue : ISignable
{
    public abstract bool TryGetDataToSign(Span<byte> destination, out int cb);
}