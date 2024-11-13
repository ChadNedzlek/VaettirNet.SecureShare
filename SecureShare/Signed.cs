using System;
using ProtoBuf;

namespace VaettirNet.SecureShare;

[ProtoContract(SkipConstructor = true)]
public class Signed<T> where T : ISignable
{
    [ProtoMember(1)]
    private T _payload;
    
    [ProtoMember(3)]
    public Guid Signer { get; }

    [ProtoMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private set; }

    public Signed(T payload, Guid signer, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
        Signer = signer;
    }

    public T DangerousGetPayload() => _payload;
}

public static class Signed
{
    public static Signed<T> Create<T>(T payload, Guid signer, ReadOnlyMemory<byte> signature)
        where T : ISignable => new(payload, signer, signature);
}