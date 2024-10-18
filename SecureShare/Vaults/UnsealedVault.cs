using System;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public class UnsealedVault
{
    private readonly SecretTransformer _transformer;

    internal UnsealedVault(LiveVaultData liveVault, SecretTransformer transformer)
    {
        _transformer = transformer;
        LiveVault = liveVault;
    }

    public LiveVaultData LiveVault { get; }

    public SecretStore<TAttributes, TProtected> GetOrCreateStore<TAttributes, TProtected>(string? name = null)
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        if (LiveVault.GetStoreOrDefault<TAttributes, TProtected>(name) is { } vault)
        {
            return new SecretStore<TAttributes, TProtected>(vault.Id.Name, vault, _transformer);
        }

        return new SecretStore<TAttributes, TProtected>(name, _transformer);
    }

    public void SaveStore<TAttributes, TProtected>(SecretStore<TAttributes, TProtected> store)
        where TAttributes : IBinarySerializable<TAttributes>, IJsonSerializable<TAttributes>
        where TProtected : IBinarySerializable<TProtected>
    {
        LiveVault.UpdateVault(store.ToSnapshot());
    }
}

public readonly record struct Signer(VaultCryptographyAlgorithm Algorithm, PrivateClientInfo Keys, ReadOnlyMemory<char> Password = default);