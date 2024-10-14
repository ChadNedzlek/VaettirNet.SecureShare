using System.Collections.Generic;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class UnsealedVault
{
    private readonly SecretTransformer _transformer;

    internal UnsealedVault(VaultData vault, SecretTransformer transformer)
    {
        _transformer = transformer;
        Vault = vault;
    }

    public VaultData Vault { get; }

    public SecretStore<TAttributes, TProtected> GetOrCreateStore<TAttributes, TProtected>()
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        IEnumerable<SealedSecretValue<TAttributes, TProtected>>? secrets = Vault.GetStoreOrDefault<TAttributes, TProtected>();
        return new SecretStore<TAttributes, TProtected>(_transformer, secrets ?? []);
    }

    public void SaveStore<TAttributes, TProtected>(SecretStore<TAttributes, TProtected> store)
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        Vault.AddStore(store);
    }
}