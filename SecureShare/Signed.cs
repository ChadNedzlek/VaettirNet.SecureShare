using System;
using ProtoBuf;

namespace VaettirNet.SecureShare;

[ProtoContract(SkipConstructor = true)]
public class Signed<T> where T : ISignable<T>
{
    [ProtoMember(1)]
    private T _payload;

    public Signed(T payload, ReadOnlyMemory<byte> signature)
    {
        _payload = payload;
        Signature = signature;
    }

    [ProtoMember(2)]
    public ReadOnlyMemory<byte> Signature { get; private set; }
    
    public Guid Authorizer => _payload.Authorizer;

    public T DangerousGetPayload() => _payload;
}

public static class Signed
{
    public static Signed<T> Create<T>(T payload, ReadOnlyMemory<byte> signature)
        where T : ISignable<T> => new(payload, signature);
}