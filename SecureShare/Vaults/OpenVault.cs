using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class OpenVaultReader<TAttributes, TProtected>
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    private readonly Dictionary<Guid, RemovedSecretRecord> _removedSecrets;
    private readonly Dictionary<Guid, SealedSecret<TAttributes, TProtected>> _secrets;

    private OpenVaultReader(VaultIdentifier id, ImmutableSortedSet<UntypedSealedSecret> secrets, IEnumerable<RemovedSecretRecord> removedSecrets)
    {
        Id = id;
        _secrets = secrets.ToDictionary(s => s.Id, s => (SealedSecret<TAttributes, TProtected>)s);
        _removedSecrets = removedSecrets.ToDictionary(s => s.Id);
    }

    public VaultIdentifier Id { get; }

    public static OpenVaultReader<TAttributes, TProtected> FromSnapshot(UntypedVaultSnapshot snapshot)
    {
        return new OpenVaultReader<TAttributes, TProtected>(snapshot.Id, snapshot.Secrets, snapshot.RemovedSecrets);
    }

    public UntypedVaultSnapshot ToSnapshot()
    {
        return new UntypedVaultSnapshot(Id, _secrets.Values, _removedSecrets.Values);
    }

    public IEnumerable<SealedSecret<TAttributes, TProtected>> GetSecrets()
    {
        return _secrets.Values;
    }

    public IEnumerable<RemovedSecretRecord> GetRemovedSecrets()
    {
        return _removedSecrets.Values;
    }

    public bool TryGet(Guid id, [MaybeNullWhen(false)] out SealedSecret<TAttributes, TProtected> secret)
    {
        return _secrets.TryGetValue(id, out secret);
    }

    public SealedSecret<TAttributes, TProtected> Get(Guid id)
    {
        return _secrets[id];
    }

    public Writer GetWriter(SecretTransformer transformer)
    {
        return new Writer(this, transformer);
    }

    public readonly struct Writer
    {
        private readonly SecretTransformer _transformer;
        private readonly OpenVaultReader<TAttributes, TProtected> _vault;

        public Writer(OpenVaultReader<TAttributes, TProtected> vault, SecretTransformer transformer)
        {
            _vault = vault;
            _transformer = transformer;
        }

        public void Update(Guid id, TAttributes attributes, TProtected @protected)
        {
            Update(new UnsealedSecret<TAttributes, TProtected>(id, attributes, @protected));
        }

        public void Update(UnsealedSecret<TAttributes, TProtected> secret)
        {
            Update(_transformer.Seal(secret));
        }

        public void Update(SealedSecret<TAttributes, TProtected> secret)
        {
            if (_vault._secrets.TryGetValue(secret.Id, out SealedSecret<TAttributes, TProtected> existing))
                _vault._secrets[secret.Id] = secret.WithVersion(existing.Version + 1);
            else
                _vault._secrets.Add(secret.Id, secret);
        }

        public Guid Add(TAttributes attributes, TProtected @protected)
        {
            UnsealedSecret<TAttributes, TProtected> secret = UnsealedSecret.Create(attributes, @protected);
            Add(secret);
            return secret.Id;
        }

        public void Add(UnsealedSecret<TAttributes, TProtected> secret)
        {
            Add(_transformer.Seal(secret));
        }

        public void Add(SealedSecret<TAttributes, TProtected> secret)
        {
            _vault._secrets.Add(secret.Id, secret);
        }

        public bool Remove(Guid id)
        {
            if (_vault._secrets.Remove(id, out SealedSecret<TAttributes, TProtected> value))
            {
                _vault._removedSecrets.Add(id, new RemovedSecretRecord(id, value.Version, value.HashBytes));
                return true;
            }

            return false;
        }
    }
}