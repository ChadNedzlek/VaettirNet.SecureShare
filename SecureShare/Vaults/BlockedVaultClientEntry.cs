using System;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

public record BlockedVaultClientEntry(Guid ClientId, string Description, ReadOnlyMemory<byte> PublicKey) : IBinarySerializable<BlockedVaultClientEntry>
{
    public static IBinarySerializer<BlockedVaultClientEntry> GetBinarySerializer() => ProtobufObjectSerializer<BlockedVaultClientEntry>.Create();
}