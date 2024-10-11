using System.Buffers;

namespace VaettirNet.SecureShare;

internal class VaultArrayPool
{
    internal static readonly ArrayPool<byte> Pool = ArrayPool<byte>.Create();
}