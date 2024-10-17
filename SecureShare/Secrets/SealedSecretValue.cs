using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract]
public class SealedSecretValue<TAttributes, TProtected> : UntypedSealedValue
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    [ProtoMember(2)]
    public required TAttributes Attributes { get; init; }

    [ProtoMember(3)]
    public required ReadOnlyMemory<byte> Protected { get; init; }

    [ProtoMember(4)]
    public required int KeyId { get; init; }
    
    public SealedSecretValue<TAttributes, TProtected> WithVersion(int version) => new()
    {
        Attributes = Attributes,
        Protected = Protected,
        KeyId = KeyId,
        Id = Id,
        HashBytes = HashBytes,
        Version = version,
    };
}

public static class SealedSecretValue
{
    public static SealedSecretValue<TAttributes, TProtected> Create<TAttributes, TProtected>(
        Guid id,
        TAttributes attributes,
        ReadOnlyMemory<byte> @protected,
        int keyId,
        ReadOnlyMemory<byte> hashBytes,
        int version = 0
    )
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected> => new()
    {
        Attributes = attributes,
        Protected = @protected,
        KeyId = keyId,
        Id = id,
        HashBytes = hashBytes,
        Version = version,
    };
}