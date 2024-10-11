using VaettirNet.SecureShare.Secrets;

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
    {
        var secrets = Vault.GetStoreOrDefault<TAttributes, TProtected>();
        return new SecretStore<TAttributes, TProtected>(_transformer, secrets ?? []);
    }

    public void SaveStore<TAttributes, TProtected>(SecretStore<TAttributes, TProtected> store)
    {
        Vault.AddStore(store);
    }
}