using System;
using System.Collections.Generic;
using System.Linq;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class OpenVault<TAttributes, TProtected>
    where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
    where TProtected : IBinarySerializable<TProtected>
{
    public VaultIdentifier Id { get; }
    private readonly Dictionary<Guid, UntypedSealedSecret> _secrets;
    private readonly Dictionary<Guid, Signed<RemovedSecretRecord>> _removedSecrets;

    private OpenVault(VaultIdentifier id, IEnumerable<UntypedSealedSecret>? secrets, IEnumerable<Signed<RemovedSecretRecord>>? removedSecrets)
    {
        Id = id;
        _secrets = secrets?.ToDictionary(s => s.Id) ?? [];
        _removedSecrets = removedSecrets?.ToDictionary(s => s.DangerousGetPayload().Id) ?? [];
    }

    public static OpenVault<TAttributes, TProtected> FromSnapshot(UntypedVaultSnapshot snapshot)
    {
        return new OpenVault<TAttributes, TProtected>(snapshot.Id, snapshot.Secrets, snapshot.RemovedSecrets);
    }

    public UntypedVaultSnapshot ToSnapshot()
    {
        return new UntypedVaultSnapshot(Id, _secrets.Values, _removedSecrets.Values);
    }

    public IEnumerable<SealedSecretSecret<TAttributes, TProtected>> GetSecrets()
    {
        return _secrets.Values.Cast<SealedSecretSecret<TAttributes, TProtected>>();
    }

    public IEnumerable<Signed<RemovedSecretRecord>> GetRemovedSecrets()
    {
        return _removedSecrets.Values;
    }

    public void RemoveSecret(Guid id, VaultCryptographyAlgorithm algorithm, PrivateClientInfo keys)
    {
        if (_secrets.Remove(id, out var value))
        {
            _removedSecrets.Add(id, algorithm.Sign(new RemovedSecretRecord(id, value.Version, value.HashBytes), keys));
        }
    }

    public void UpdateSecret(SealedSecretSecret<TAttributes, TProtected> secret)
    {
        if (_secrets.TryGetValue(secret.Id, out var existing))
        {
            _secrets[secret.Id] = secret.WithVersion(existing.Version + 1);
        }
        else
        {
            _secrets.Add(secret.Id, secret);
        }
    }
}