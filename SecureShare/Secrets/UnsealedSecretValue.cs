using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public record UnsealedSecretValue<TAttributes, TProtected>(Guid Id, TAttributes Attributes, TProtected Protected)
    : SecretValue<TAttributes>(Id, Attributes)
    where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>;