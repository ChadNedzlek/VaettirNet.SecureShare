using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Secrets;

public abstract class SecretValue<TAttributes>(Guid Id, TAttributes Attributes)
    where TAttributes : IJsonSerializable<TAttributes>, IBinarySerializable<TAttributes>;