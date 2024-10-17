using System;
using System.Collections.Immutable;
using ProtoBuf;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract]
public class VaultDataSnapshot : BinarySerializable<VaultDataSnapshot>
{
    [ProtoMember(1)]
    public required ImmutableList<VaultClientEntry> Clients { get; init; }
    [ProtoMember(2)]
    public required ImmutableList<BlockedVaultClientEntry> BlockedClients { get; init; }
    [ProtoMember(3)]
    public required ImmutableList<Signed<ClientModificationRecord>> ClientModificications { get; init; }
    [ProtoMember(4)]
    [ProtoMap]
    public required ImmutableDictionary<VaultIdentifier, UntypedVaultSnapshot> Vaults { get; init; }
    [ProtoMember(5)]
    public required ReadOnlyMemory<byte> ManifestSignature { get; init; }
}