using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using JetBrains.Annotations;
using VaettirNet.SecureShare.Serialization;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Secrets;

public class SecretStore<TAttributes, TProtected> : IEnumerable<SealedSecretSecret<TAttributes, TProtected>> where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes> where TProtected : IBinarySerializable<TProtected>
{
    private readonly Dictionary<Guid, SealedSecretSecret<TAttributes, TProtected>> _secrets;
    private readonly List<Signed<RemovedSecretRecord>> _deleted;
    private readonly SecretTransformer _transformer;
    private readonly string? _name;

    public SecretStore(string? name, SecretTransformer transformer)
    {
        _name = name;
        _transformer = transformer;
        _secrets = [];
        _deleted = [];
    }

    public SecretStore(string? name, UntypedVaultSnapshot vault, SecretTransformer transformer)
    {
        _name = name;
        _transformer = transformer;
        _secrets = vault.Secrets?.Cast<SealedSecretSecret<TAttributes, TProtected>>().ToDictionary(s => s.Id) ?? [];
        _deleted = vault.RemovedSecrets?.ToList() ?? [];
    }

    public UntypedVaultSnapshot ToSnapshot()
    {
        return new UntypedVaultSnapshot(VaultIdentifier.Create<TAttributes, TProtected>(_name), _secrets.Values, _deleted);
    }

    public IEnumerator<SealedSecretSecret<TAttributes, TProtected>> GetEnumerator()
    {
        return _secrets.Values.GetEnumerator();
    }

    [MustDisposeResource]
    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_secrets.Values).GetEnumerator();
    }

    public UnsealedSecretValue<TAttributes, TProtected> GetUnsealed(Guid id) => _transformer.Unseal(Get(id));

    public SealedSecretSecret<TAttributes, TProtected> Get(Guid id)
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

    public void Set(SealedSecretSecret<TAttributes, TProtected> secret)
    {
        if (_secrets.TryGetValue(secret.Id, out var existing))
        {
            _secrets[secret.Id] = secret.WithVersion(existing.Version + 1);
        }
        else
        {
            _secrets.Add(secret.Id, secret.WithVersion(1));
        }
    }

    public void Remove(Guid id, VaultCryptographyAlgorithm algorithm, PrivateClientInfo key) => Remove(id, algorithm, key, default);

    public void Remove(Guid id, VaultCryptographyAlgorithm algorithm, PrivateClientInfo key, ReadOnlySpan<char> password)
    {
        if (_secrets.Remove(id, out SealedSecretSecret<TAttributes, TProtected>? secret))
        {
            _deleted.Add(algorithm.Sign(new RemovedSecretRecord(secret.Id, secret.Version, secret.HashBytes), key, password));
        }
    }
}