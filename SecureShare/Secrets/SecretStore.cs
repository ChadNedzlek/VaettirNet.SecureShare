using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Secrets;

public class OpenVaultDEPRECATED<TAttributes, TProtected> : IEnumerable<SealedSecret<TAttributes, TProtected>>
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    private readonly Dictionary<Guid, SealedSecret<TAttributes, TProtected>> _secrets;
    private readonly HashSet<RemovedSecretRecord> _deleted;
    private readonly SecretTransformer _transformer;
    private readonly string _name;

    public OpenVaultDEPRECATED(string name, SecretTransformer transformer)
    {
        _name = name;
        _transformer = transformer;
        _secrets = [];
        _deleted = [];
    }

    public OpenVaultDEPRECATED(string name, UntypedVaultSnapshot vault, SecretTransformer transformer)
    {
        _name = name;
        _transformer = transformer;
        _secrets = vault.Secrets.Cast<SealedSecret<TAttributes, TProtected>>().ToDictionary(s => s.Id);
        _deleted = new HashSet<RemovedSecretRecord>(vault.RemovedSecrets, RemovedSecretRecord.Comparer.Instance);
    }

    public UntypedVaultSnapshot ToSnapshot()
    {
        return new UntypedVaultSnapshot(VaultIdentifier.Create<TAttributes, TProtected>(_name), _secrets.Values, _deleted);
    }

    public IEnumerator<SealedSecret<TAttributes, TProtected>> GetEnumerator()
    {
        return _secrets.Values.GetEnumerator();
    }

    [MustDisposeResource]
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_secrets.Values).GetEnumerator();
    }

    public UnsealedSecret<TAttributes, TProtected> GetUnsealed(Guid id) => _transformer.Unseal(Get(id));

    public SealedSecret<TAttributes, TProtected> Get(Guid id)
    {
        lock (_secrets)
        {
            return _secrets[id];
        }
    }

    public Guid Add(TAttributes attributes, TProtected @protected)
    {
        Guid id = Guid.NewGuid();
        Set(new UnsealedSecret<TAttributes, TProtected>(id, attributes, @protected));
        return id;
    }

    public void Set(UnsealedSecret<TAttributes, TProtected> value) => Set(_transformer.Seal(value));

    public void Set(SealedSecret<TAttributes, TProtected> secret)
    {
        if (_secrets.TryGetValue(secret.Id, out SealedSecret<TAttributes, TProtected> existing))
        {
            _secrets[secret.Id] = secret.WithVersion(existing.Version + 1);
        }
        else
        {
            _secrets.Add(secret.Id, secret.WithVersion(1));
        }
    }

    public void Remove(Guid id)
    {
        if (_secrets.Remove(id, out SealedSecret<TAttributes, TProtected> secret))
        {
            _deleted.Add(new RemovedSecretRecord(secret.Id, secret.Version, secret.HashBytes));
        }
    }
}