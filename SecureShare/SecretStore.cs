using System.Collections;
using JetBrains.Annotations;

namespace SecureShare;

public class SecretStore<TAttributes, TProtected> : IEnumerable<SealedSecretValue<TAttributes, TProtected>>
{
    private readonly SecretTransformer _transformer;
    private readonly Dictionary<Guid, SealedSecretValue<TAttributes, TProtected>> _closedSecrets;

    public SecretStore(
        SecretTransformer transformer,
        IEnumerable<SealedSecretValue<TAttributes, TProtected>>? closedSecrets = null)
    {
        _transformer = transformer;
        _closedSecrets = closedSecrets?.ToDictionary(s => s.Id) ?? [];
    }

    public UnsealedSecretValue<TAttributes, TProtected>? GetUnsealed(Guid id) =>
        _closedSecrets[id] is {} value ? _transformer.Unseal(value) : null;
    public SealedSecretValue<TAttributes, TProtected>? Get(Guid id) =>
        _closedSecrets.GetValueOrDefault(id);
    
    public void Set(UnsealedSecretValue<TAttributes, TProtected> value) =>
        _closedSecrets[value.Id] = _transformer.Seal(value);
    public void Set(SealedSecretValue<TAttributes, TProtected> value) =>
        _closedSecrets[value.Id] = value;

    public IEnumerator<SealedSecretValue<TAttributes, TProtected>> GetEnumerator()
    {
        return _closedSecrets.Values.GetEnumerator();
    }

    [MustDisposeResource]
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_closedSecrets).GetEnumerator();
    }
}