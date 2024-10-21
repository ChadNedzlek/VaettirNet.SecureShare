using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ProtoBuf;
using VaettirNet.SecureShare.Secrets;
using VaettirNet.SecureShare.Serialization;

namespace VaettirNet.SecureShare.Vaults;

[ProtoContract(SkipConstructor = true)]
public class VaultDataSnapshot : BinarySerializable<VaultDataSnapshot>, ISignable
{
    [ProtoMember(1)]
    public ImmutableList<VaultClientEntry>? Clients { get; private set; }

    [ProtoMember(2)]
    public ImmutableList<BlockedVaultClientEntry>? BlockedClients { get; private set; }

    [ProtoMember(3)]
    public ImmutableList<Signed<ClientModificationRecord>>? ClientModifications { get; private set; }

    [ProtoMember(4)]
    public ImmutableList<UntypedVaultSnapshot>? Vaults { get; private set; }
    
    [ProtoMember(5)]
    public uint Version { get; private set; }

    public VaultDataSnapshot(
        IEnumerable<VaultClientEntry>? clients,
        IEnumerable<BlockedVaultClientEntry>? blockedClients,
        IEnumerable<Signed<ClientModificationRecord>>? clientModifications,
        IEnumerable<UntypedVaultSnapshot>? vaults,
        uint version = 1
    )
    {
        Version = version;
        Clients = clients?.OrderBy(c => c.ClientId).ToImmutableList();
        BlockedClients = blockedClients?.OrderBy(c => c.ClientId).ToImmutableList();
        ClientModifications = clientModifications?.ToImmutableList();
        Vaults = vaults?.OrderBy(v => v.Id.Name).ToImmutableList();
    }

    public bool TryGetDataToSign(Span<byte> destination, out int cb)
    {
        using IncrementalHash hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        AppendInt(hasher, Clients?.Count ?? 0);
        Span<byte> buffer = stackalloc byte[1000];
        foreach (var client in Clients ?? [])
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }
        
        AppendInt(hasher, BlockedClients?.Count ?? 0);
        foreach (var client in BlockedClients ?? [])
        {
            AppendGuid(hasher, client.ClientId, buffer);
        }

        AppendInt(hasher, Vaults?.Count ?? 0);
        foreach (UntypedVaultSnapshot vault in Vaults ?? [])
        {
            AppendString(hasher, vault.Id.Name, buffer);
            AppendString(hasher, vault.Id.AttributeTypeName, buffer);
            AppendString(hasher, vault.Id.ProtectedTypeName, buffer);
            
            AppendInt(hasher, vault.Secrets?.Count ?? 0);
            foreach (UntypedSealedSecret secret in vault.Secrets ?? [])
            {
                AppendGuid(hasher, secret.Id, buffer);
            }
            
            AppendInt(hasher, vault.RemovedSecrets?.Count ?? 0);
            foreach (Signed<RemovedSecretRecord> secret in vault.RemovedSecrets ?? [])
            {
                AppendGuid(hasher, secret.DangerousGetPayload().Id, buffer);
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
            var len = Encoding.UTF8.GetBytes(value, buffer);
            h.AppendData(buffer[..len]);
        }
    }
}

public static class VaultDataSnapshotExtensions
{
    public static bool TryGetSignerPublicInfo(this Signed<VaultDataSnapshot> self, out PublicClientInfo signer)
    {
        VaultClientEntry? info = self.DangerousGetPayload().Clients?.FirstOrDefault(c => c.ClientId == self.Signer);
        if (info == null)
        {
            signer = default;
            return false;
        }

        signer = info.PublicInfo;
        return true;
    }
}