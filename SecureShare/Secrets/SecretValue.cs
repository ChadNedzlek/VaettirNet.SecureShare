using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public abstract record SecretValue<TAttributes>(Guid Id, TAttributes Attributes)
    where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>;