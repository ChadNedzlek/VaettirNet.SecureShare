using System.Threading;
using System.Threading.Tasks;
using VaettirNet.SecureShare.Vaults;

namespace VaettirNet.SecureShare.Sync;

public interface IVaultSyncClient
{
    Task<GetVaultResult> GetVaultAsync(CancellationToken cancellationToken);
    Task<PutVaultResult> PutVaultAsync(ValidatedVaultDataSnapshot snapshot, string? etag = null, bool force = false, CancellationToken cancellationToken = default);
}