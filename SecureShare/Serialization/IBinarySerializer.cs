using System;

namespace VaettirNet.SecureShare.Serialization;

public interface IBinarySerializer<T> where T : IBinarySerializable<T>
{
    bool TrySerialize(T value, Span<byte> destination, out int bytesWritten);
    T Deserialize(ReadOnlySpan<byte> source);
}