using System;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare;

public readonly struct Signed<T> where T : ISignable<T>
{
    public ReadOnlyMemory<byte> Signature { get; }
    
    private readonly T _payload;
    public Guid Authorizer => _payload.Authorizer;

    public Signed(T payload, ReadOnlyMemory<byte> signature)
    {
        Signature = signature;
        _payload = payload;
    }

    public T DangerousGetPayload() => _payload;
}