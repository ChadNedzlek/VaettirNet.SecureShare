using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class UnvalidatedVaultDataSnapshot : BinarySerializable<UnvalidatedVaultDataSnapshot>, ISignable
{
    [ProtoMember(1)]
    public ImmutableSortedSet<VaultClientEntry>? Clients { get; private set; }

    [ProtoMember(2)]
    public ImmutableSortedSet<BlockedVaultClientEntry>? BlockedClients { get; private set; }

    [ProtoMember(3)]
    public ImmutableList<Signed<ClientModificationRecord>>? ClientModifications { get; private set; }

    [ProtoMember(4)]
    public ImmutableSortedSet<UntypedVaultSnapshot>? Vaults { get; private set; }
    
    [ProtoMember(5)]
    public uint Version { get; private set; }

    public UnvalidatedVaultDataSnapshot(
        IEnumerable<VaultClientEntry>? clients,
        IEnumerable<BlockedVaultClientEntry>? blockedClients,
        IEnumerable<Signed<ClientModificationRecord>>? clientModifications,
        IEnumerable<UntypedVaultSnapshot>? vaults,
        uint version = 1
    )
    {
        Version = version;
        Clients = clients?.ToImmutableSortedSet();
        BlockedClients = blockedClients?.ToImmutableSortedSet();
        ClientModifications = clientModifications?.ToImmutableList();
        Vaults = vaults?.ToImmutableSortedSet();
    }

    public bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        AppendInt(hasher, Clients?.Count ?? 0);
        Span<byte> buffer = stackalloc byte[1000];
        foreach (VaultClientEntry? client in Clients ?? [])
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }
        
        AppendInt(hasher, BlockedClients?.Count ?? 0);
        foreach (BlockedVaultClientEntry? client in BlockedClients ?? [])
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }

        AppendInt(hasher, Vaults?.Count ?? 0);
        foreach (UntypedVaultSnapshot vault in Vaults ?? [])
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