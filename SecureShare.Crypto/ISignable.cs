using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Crypto;

public interface ISignable
{
    bool TryGetDataToSign(Span<byte> destination, out int cb);
}

public interface IBinarySignable<TSelf> : ISignable, IBinarySerializable<TSelf>
    where TSelf : IBinarySerializable<TSelf>
{
    bool ISignable.TryGetDataToSign(Span<byte> destination, out int cb)
    {
        return TSelf.GetBinarySerializer().TrySerialize((TSelf)this, destination, out cb);
    }
}