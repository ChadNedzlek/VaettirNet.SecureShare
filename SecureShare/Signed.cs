using System;
using ProtoBuf;

namespace VaettirNet.SecureShare;

[ProtoContract(SkipConstructor = true)]
public class Signed<T>
    where T : ISignable
{
    [ProtoMember(1)] private T _payload;

    public Signed(T payload, Guid signer, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
        Signer = signer;
    }

    [ProtoMember(3)]
    public Guid Signer { get; }

    [ProtoMember(2)]
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