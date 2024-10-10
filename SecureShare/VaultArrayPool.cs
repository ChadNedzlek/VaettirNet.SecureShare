using System.Buffers;

namespace SecureShare;

internal class VaultArrayPool
{
    internal static readonly ArrayPool<byte> Pool = ArrayPool<byte>.Create();
}