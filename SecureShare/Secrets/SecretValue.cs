using System;

namespace VaettirNet.SecureShare.Secrets;

public abstract class SecretValue<TAttributes>
{
    public SecretValue(Guid id, TAttributes attributes)
    {
        Id = id;
        Attributes = attributes;
    }

    public Guid Id { get; }
    public TAttributes Attributes { get; }
}