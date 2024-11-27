using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using VaettirNet.PackedBinarySerialization.Attributes;
using VaettirNet.SecureShare.Crypto;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[PackedBinarySerializable(IncludeNonPublic = true)]
public class UnvalidatedVaultDataSnapshot : BinarySerializable<UnvalidatedVaultDataSnapshot>, ISignable
{
    [PackedBinaryMember(1)]
    private ImmutableSortedSet<VaultClientEntry>? _clients;
    public ImmutableSortedSet<VaultClientEntry> Clients => _clients ?? [];

    [PackedBinaryMember(2)]
    private ImmutableSortedSet<BlockedVaultClientEntry>? _blockedClients;
    public ImmutableSortedSet<BlockedVaultClientEntry> BlockedClients => _blockedClients ?? ImmutableSortedSet<BlockedVaultClientEntry>.Empty;

    [PackedBinaryMember(3)]
    private ImmutableList<Signed<ClientModificationRecord>>? _clientModifications;
    public ImmutableList<Signed<ClientModificationRecord>> ClientModifications => _clientModifications ?? ImmutableList<Signed<ClientModificationRecord>>.Empty;

    [PackedBinaryMember(4)]
    private ImmutableSortedSet<UntypedVaultSnapshot>? _vaults;
    public ImmutableSortedSet<UntypedVaultSnapshot> Vaults => _vaults ?? ImmutableSortedSet<UntypedVaultSnapshot>.Empty;

    [PackedBinaryMember(5)]
    public uint Version { get; private set; }

    public UnvalidatedVaultDataSnapshot(
        IEnumerable<VaultClientEntry> clients,
        IEnumerable<BlockedVaultClientEntry> blockedClients,
        IEnumerable<Signed<ClientModificationRecord>> clientModifications,
        IEnumerable<UntypedVaultSnapshot> vaults,
        uint version = 1
    )
    {
        Version = version;
        _clients = clients.ToImmutableSortedSet();
        _blockedClients = blockedClients.ToImmutableSortedSet();
        _clientModifications = clientModifications.ToImmutableList();
        _vaults = vaults.ToImmutableSortedSet();
    }

    public bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        AppendInt(hasher, Clients.Count);
        Span<byte> buffer = stackalloc byte[1000];
        foreach (VaultClientEntry client in Clients)
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }
        
        AppendInt(hasher, BlockedClients.Count);
        foreach (BlockedVaultClientEntry client in BlockedClients)
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }

        AppendInt(hasher, Vaults.Count);
        foreach (UntypedVaultSnapshot vault in Vaults)
        {
            AppendString(hasher, vault.Id.Name, buffer);
            AppendString(hasher, vault.Id.AttributeTypeName, buffer);
            AppendString(hasher, vault.Id.ProtectedTypeName, buffer);
            
            AppendInt(hasher, vault.Secrets.Count);
            foreach (UntypedSealedSecret secret in vault.Secrets)
            {
                AppendGuid(hasher, secret.Id, buffer);
            }
            
            AppendInt(hasher, vault.RemovedSecrets.Count);
            foreach (RemovedSecretRecord secret in vault.RemovedSecrets)
            {
                AppendGuid(hasher, secret.Id, buffer);
            }
        }
        
        return hasher.TryGetHashAndReset(destination, out cb);
        
        static void AppendGuid(IncrementalHash h, Guid value, Span<byte> buffer)
        {
            value.TryWriteBytes(buffer);
            h.AppendData(buffer[..16]);
        }
        
        static void AppendInt(IncrementalHash h, int count)
        {
            h.AppendData(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref count, 1)));
        }
        
        static void AppendString(IncrementalHash h, string value, Span<byte> buffer)
        {
            AppendInt(h, value.Length);
            int len = Encoding.UTF8.GetBytes(value, buffer);
            h.AppendData(buffer[..len]);
        }
    }
}