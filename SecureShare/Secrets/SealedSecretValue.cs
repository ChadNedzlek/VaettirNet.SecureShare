using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public static class SealedSecretValue
{
    public static SealedSecretSecret<TAttributes, TProtected> Create<TAttributes, TProtected>(
        Guid id,
        TAttributes attributes,
        ReadOnlyMemory<byte> @protected,
        int keyId,
        ReadOnlyMemory<byte> hashBytes,
        uint version = 0
    )
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected> => new(id, version, hashBytes, attributes, @protected, keyId);
}