using System.Text.Json;

namespace SecureShare;

public class ClosedSecretValue<TAttributes> : SecretValue<TAttributes>
{
    public ClosedSecretValue(Guid id, TAttributes attributes, byte[] @protected, int keyId, int version) : base(id, attributes)
    {
        Protected = @protected;
        KeyId = keyId;
        Version = version;
    }

    public int KeyId { get; }
    public int Version { get; }
    public byte[] Protected { get; }
}

public class SealedSecretValue<TAttributes, TProtected> : ClosedSecretValue<TAttributes>
{
    public SealedSecretValue(Guid id, TAttributes attributes, byte[] @protected, int keyId, int version) : base(id,
        attributes,
        @protected,
        keyId,
        version)
    {
    }
}