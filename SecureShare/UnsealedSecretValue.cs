using System;

namespace SecureShare;

public class UnsealedSecretValue<TAttributes, TProtected> : SecretValue<TAttributes>
{
    public UnsealedSecretValue(Guid id, TAttributes attributes, TProtected @protected) : base(id, attributes)
    {
        Protected = @protected;
    }

    public TProtected Protected { get; }
}