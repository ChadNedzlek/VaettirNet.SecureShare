using System;
using System.Collections.Immutable;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public record SealedSecretValue<TAttributes, TProtected>(
    Guid Id,
    TAttributes Attributes,
    ReadOnlyMemory<byte> Protected,
    int KeyId,
    int Version,
    ReadOnlyMemory<byte> HashBytes
)
    : SealedSecretValue<TAttributes>(Id, Attributes, Protected, KeyId, Version, HashBytes)
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>;

public abstract record SealedSecretValue<TAttributes>(Guid Id, TAttributes Attributes, ReadOnlyMemory<byte> Protected, int KeyId, int Version, ReadOnlyMemory<byte> HashBytes)
    : SecretValue<TAttributes>(Id, Attributes)
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>;