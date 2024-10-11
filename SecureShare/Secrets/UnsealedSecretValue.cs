using System;

namespace VaettirNet.SecureShare.Secrets;

public class UnsealedSecretValue<TAttributes, TProtected> : SecretValue<TAttributes>
{
    public UnsealedSecretValue(Guid id, TAttributes attributes, TProtected @protected) : base(id, attributes)
    {
        Protected = @protected;
    }

    public TProtected Protected { get; }
}