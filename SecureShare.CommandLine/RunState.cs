using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Sync;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.CommandLine;

internal class RunState
{
    public VaultCryptographyAlgorithm Algorithm { get; } = new();
    public PrivateKeyInfo Keys { get; set; }
    public ValidatedVaultDataSnapshot LoadedSnapshot { get; set; }
    public VaultManager VaultManager { get; set; }
    public OpenVaultReader<LinkMetadata, LinkData> Store { get; set; }
    public IVaultSyncClient Sync { get; set; }

    public RefSigner Signer => new(Algorithm, Keys);
}