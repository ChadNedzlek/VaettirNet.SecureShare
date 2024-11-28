using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;

namespace VaettirNet.TreeFormat;

/// <summary>
/// Base class for NodeValue. Should be immutable.
/// </summary>
[PackedBinarySerializable]
public abstract class NodeValue : ISignable
{
    public abstract bool TryGetDataToSign(Span<byte> destination, out int cb);
}