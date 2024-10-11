using System;
using System.Collections.Immutable;

namespace VaettirNet.SecureShare.Vaults;

public record VaultClientEntry(
    Guid ClientId,
    string Description,
    ImmutableArray<byte> PublicKey,
    ImmutableArray<byte> EncryptedSharedKey,
    Guid AuthorizedByClientId);