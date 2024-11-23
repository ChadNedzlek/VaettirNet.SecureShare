using System;
using VaettirNet.PackedBinarySerialization.Attributes;

namespace VaettirNet.SecureShare;

[PackedBinarySerializable]
public class Signed<T>
    where T : ISignable
{
    [PackedBinaryMember(1)] private T _payload;

    public Signed(T payload, Guid signer, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
        Signer = signer;
    }

    [PackedBinaryMember(3)]
    public Guid Signer { get; }

    [PackedBinaryMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private set; }

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