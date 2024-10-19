using VaettirNet.SecureShare;
using VaettirNet.SecureShare.Vaults;

namespace sec;

internal class RunState
{
    public VaultCryptographyAlgorithm Algorithm { get; } = new();
    public PrivateClientInfo Keys { get; set; }
    public VaultDataSnapshot LoadedSnapshot { get; set; }
    public VaultManager VaultManager { get; set; }
    public OpenVault<LinkMetadata, LinkData> Store { get; set; }

    public VaultDataSnapshot VaultSnapshot => VaultManager?.Vault.GetSnapshot() ?? LoadedSnapshot;
}