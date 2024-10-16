using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract]
public class SealedSecretValue<TAttributes, TProtected>
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    [ProtoMember(1)]
    public Guid Id { get; private set; }

    [ProtoMember(2)]
    public TAttributes Attributes { get; private set; }

    [ProtoMember(3)]
    public ReadOnlyMemory<byte> Protected { get; private set; }

    [ProtoMember(4)]
    public int KeyId { get; private set; }

    [ProtoMember(5)]
    public int Version { get; private set; }

    [ProtoMember(6)]
    public ReadOnlyMemory<byte> HashBytes { get; private set; }

    public SealedSecretValue(
        Guid id,
        TAttributes attributes,
        ReadOnlyMemory<byte> @protected,
        int keyId,
        ReadOnlyMemory<byte> hashBytes
    ) : this(id, attributes, @protected, keyId, 0, hashBytes)
    {
    }

    public SealedSecretValue(
        Guid id,
        TAttributes attributes,
        ReadOnlyMemory<byte> @protected,
        int keyId,
        int version,
        ReadOnlyMemory<byte> hashBytes
    )
    {
        Id = id;
        Attributes = attributes;
        Protected = @protected;
        KeyId = keyId;
        Version = version;
        HashBytes = hashBytes;
    }

    public SealedSecretValue<TAttributes, TProtected> WithVersion(int version) => new(Id, Attributes, Protected, KeyId, version, HashBytes);
}