using System;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Crypto;

[PackedBinarySerializable(IncludeNonPublic = true)]
public class Signed<T> : IBinarySerializable<Signed<T>>
    where T : ISignable
{
    [PackedBinaryMember(1)] private readonly T _payload;

    public Signed(T payload, Guid signer, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
        Signer = signer;
    }

    [PackedBinaryMember(3)]
    public Guid Signer { get; private init; }

    [PackedBinaryMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private init; }

    public static IBinarySerializer<Signed<T>> GetBinarySerializer()
    {
        return PackedBinaryObjectSerializer<Signed<T>>.Create();
    }

    public T DangerousGetPayload()
    {
        return _payload;
    }
}

public static class Signed
{
    public static Signed<T> Create<T>(T payload, Guid signer, ReadOnlyMemory<byte> signature)
        where T : ISignable
    {
        return new Signed<T>(payload, signer, signature);
    }
}