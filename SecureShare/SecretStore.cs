using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;

namespace SecureShare;

public class SecretStore<TAttributes, TProtected> : IEnumerable<SealedSecretValue<TAttributes, TProtected>>
{
    private readonly Dictionary<Guid, SealedSecretValue<TAttributes, TProtected>> _closedSecrets;
    private readonly SecretTransformer _transformer;

    public SecretStore(
        SecretTransformer transformer,
        IEnumerable<SealedSecretValue<TAttributes, TProtected>>? closedSecrets = null
    )
    {
        _transformer = transformer;
        _closedSecrets = closedSecrets?.ToDictionary(s => s.Id) ?? [];
    }

    public IEnumerator<SealedSecretValue<TAttributes, TProtected>> GetEnumerator()
    {
        return _closedSecrets.Values.GetEnumerator();
    }

    [MustDisposeResource]
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_closedSecrets).GetEnumerator();
    }

    public UnsealedSecretValue<TAttributes, TProtected>? GetUnsealed(Guid id)
    {
        return _transformer.Unseal(_closedSecrets[id]);
    }

    public SealedSecretValue<TAttributes, TProtected> Get(Guid id)
    {
        return _closedSecrets[id];
    }

    public Guid Add(TAttributes attributes, TProtected @protected)
    {
        Guid id = Guid.NewGuid();
        Set(new UnsealedSecretValue<TAttributes, TProtected>(id, attributes, @protected));
        return id;
    }

    public void Set(UnsealedSecretValue<TAttributes, TProtected> value)
    {
        _closedSecrets[value.Id] = _transformer.Seal(value);
    }

    public void Set(SealedSecretValue<TAttributes, TProtected> value)
    {
        _closedSecrets[value.Id] = value;
    }
}