using System;

namespace VaettirNet.SecureShare.Vaults;

public record BlockedVaultClientEntry(
    Guid ClientId,
    string Description,
    ReadOnlyMemory<byte> PublicKey,
    Guid BlockedByClientId);