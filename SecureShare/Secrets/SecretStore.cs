using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using JetBrains.Annotations;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Secrets;

public class SecretStore<TAttributes, TProtected> : IEnumerable<SealedSecretValue<TAttributes, TProtected>> where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
{
    private readonly Dictionary<Guid, SealedSecretValue<TAttributes, TProtected>> _secrets;
    private readonly Dictionary<Guid, ReadOnlyMemory<byte>> _deleted;
    private readonly SecretTransformer _transformer;

    public SecretStore(SecretTransformer transformer)
    {
        _transformer = transformer;
        _secrets = [];
        _deleted = [];
    }

    public SecretStore(SecretTransformer transformer, TypedVault vault)
    {
        _transformer = transformer;
        _secrets = vault.SealedSecrets.Cast<SealedSecretValue<TAttributes, TProtected>>().ToDictionary(s => s.Id);
        _deleted = vault.DeletedSecrets.ToDictionary();
    }

    public TypedVault ToTypedVault()
    {
        return new TypedVault(typeof(TAttributes), typeof(TProtected), _secrets.Values, _deleted.ToImmutableDictionary());
    }

    public IEnumerator<SealedSecretValue<TAttributes, TProtected>> GetEnumerator()
    {
        return _secrets.Values.GetEnumerator();
    }

    [MustDisposeResource]
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_secrets.Values).GetEnumerator();
    }

    public UnsealedSecretValue<TAttributes, TProtected> GetUnsealed(Guid id) => _transformer.Unseal(Get(id));

    public SealedSecretValue<TAttributes, TProtected> Get(Guid id)
    {
        lock (_secrets)
        {
            return _secrets[id];
        }
    }

    public Guid Add(TAttributes attributes, TProtected @protected)
    {
        Guid id = Guid.NewGuid();
        Set(new UnsealedSecretValue<TAttributes, TProtected>(id, attributes, @protected));
        return id;
    }

    public void Set(UnsealedSecretValue<TAttributes, TProtected> value) => Set(_transformer.Seal(value));
    
    public void Set(SealedSecretValue<TAttributes, TProtected> value)
    {
        lock (_secrets)
        {
            if (_secrets.TryGetValue(value.Id, out var existing))
            {
                _secrets[value.Id] = value with { Version = existing.Version + 1 };
            }
            else
            {
                _secrets.Add(value.Id, value with {Version = 1});
            }
        }
    }

    public void Remove(Guid id)
    {
        lock (_secrets)
        {
            if (_secrets.Remove(id, out var secret))
            {
                _deleted.Add(id, secret.HashBytes);
            }
        }
    }
}