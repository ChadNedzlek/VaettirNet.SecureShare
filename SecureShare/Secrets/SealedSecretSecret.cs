using System;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

[ProtoContract(SkipConstructor = true)]
public class SealedSecretSecret<TAttributes, TProtected> : UntypedSealedSecret
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    [ProtoMember(2)]
    public TAttributes Attributes { get; private set; }

    [ProtoMember(3)]
    public ReadOnlyMemory<byte> Protected { get; private set; }

    [ProtoMember(4)]
    public int KeyId { get; private set; }

    public SealedSecretSecret(Guid id, uint version, ReadOnlyMemory<byte> hashBytes, TAttributes attributes, ReadOnlyMemory<byte> @protected, int keyId) : base(id, version, hashBytes)
    {
        Attributes = attributes;
        Protected = @protected;
        KeyId = keyId;
    }

    public SealedSecretSecret<TAttributes, TProtected> WithVersion(uint version) => new(Id, version, HashBytes, Attributes, Protected, KeyId);
}