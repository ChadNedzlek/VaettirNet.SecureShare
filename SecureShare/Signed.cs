using System;
using ProtoBuf;

namespace VaettirNet.SecureShare;

[ProtoContract(SkipConstructor = true)]
public class Signed<T> where T : ISignable
{
    [ProtoMember(1)]
    private T _payload;

    public Signed(T payload, Guid signer, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
        Signer = signer;
    }

    [ProtoMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private set; }
    
    public Guid Signer { get; }

    public T DangerousGetPayload() => _payload;
}

public static class Signed
{
    public static Signed<T> Create<T>(T payload, Guid signer, ReadOnlyMemory<byte> signature)
        where T : ISignable => new(payload, signer, signature);
}