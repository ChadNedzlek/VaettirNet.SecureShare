using System;
using System.Collections.Immutable;

namespace SecureShare;

public class SealedSecretValue<TAttributes, TProtected> : SealedSecretValue<TAttributes>
{
    public SealedSecretValue(Guid id, TAttributes attributes, ImmutableArray<byte> @protected, int keyId, int version) : base(id,
        attributes,
        @protected,
        keyId,
        version)
    {
    }
}

public class SealedSecretValue<TAttributes> : SecretValue<TAttributes>
{
    public SealedSecretValue(Guid id, TAttributes attributes, ImmutableArray<byte> @protected, int keyId, int version) : base(id, attributes)
    {
        Protected = @protected;
        KeyId = keyId;
        Version = version;
    }

    public int KeyId { get; }
    public int Version { get; }
    public ImmutableArray<byte> Protected { get; }
}